/*
 * The MIT License
 *
 * Copyright 2018 CloudBees, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

package io.jenkins.plugins.pipeline_log_fluentd_cloudwatch;

import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.auth.BasicSessionCredentials;
import com.amazonaws.auth.DefaultAWSCredentialsProviderChain;
import com.amazonaws.auth.InstanceProfileCredentialsProvider;
import com.amazonaws.services.securitytoken.AWSSecurityTokenServiceClientBuilder;
import com.amazonaws.services.securitytoken.model.AssumeRoleRequest;
import com.amazonaws.services.securitytoken.model.AssumeRoleResult;
import com.cloudbees.jenkins.plugins.awscredentials.AWSCredentialsImpl;
import com.cloudbees.jenkins.plugins.awscredentials.BaseAmazonWebServicesCredentials;
import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.SystemCredentialsProvider;
import hudson.ExtensionList;
import hudson.model.Computer;
import hudson.model.TaskListener;
import hudson.slaves.ComputerListener;
import hudson.slaves.SlaveComputer;
import hudson.util.FormValidation;
import hudson.util.StreamTaskListener;
import io.jenkins.plugins.aws.global_configuration.CredentialsAwsGlobalConfiguration;
import java.io.IOException;
import java.util.UUID;
import java.util.logging.Formatter;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;
import java.util.logging.SimpleFormatter;
import java.util.logging.StreamHandler;
import jenkins.security.MasterToSlaveCallable;
import static org.hamcrest.Matchers.*;
import org.jenkinsci.plugins.workflow.log.LogStorage;
import org.jenkinsci.plugins.workflow.log.LogStorageTestBase;
import static org.junit.Assume.*;
import org.junit.Before;
import org.junit.Rule;
import org.jvnet.hudson.test.LoggerRule;
import org.jvnet.hudson.test.TestExtension;

public class PipelineBridgeTest extends LogStorageTestBase {

    private static final String LOG_STREAM_NAME = "PipelineBridgeTest";

    @Rule public LoggerRule logging = new LoggerRule().recordPackage(PipelineBridge.class, Level.FINER);
    private String id;

    @Before public void setUp() throws Exception {
        String logGroupName = System.getenv("CLOUDWATCH_LOG_GROUP_NAME");
        assumeThat("must define $CLOUDWATCH_LOG_GROUP_NAME", logGroupName, notNullValue());
        String role = System.getenv("AWS_ROLE");
        String credentialsId = null;
        if (role != null) {
            credentialsId = "aws";
            SystemCredentialsProvider.getInstance().getCredentials().add(new AssumedRoleCreds(role, CredentialsScope.GLOBAL, credentialsId, null));
            CredentialsAwsGlobalConfiguration.get().setCredentialsId(credentialsId);
        }
        CloudWatchAwsGlobalConfiguration configuration = ExtensionList.lookupSingleton(CloudWatchAwsGlobalConfiguration.class);
        FormValidation logGroupNameValidation = configuration.validate(logGroupName, null, credentialsId);
        assumeThat(logGroupNameValidation.toString(), logGroupNameValidation.kind, is(FormValidation.Kind.OK));
        configuration.setLogGroupName(logGroupName);
        id = UUID.randomUUID().toString();
    }

    // TODO consider whether this should be moved into LoggerRule
    @TestExtension public static final class RemoteLogs extends ComputerListener {
        @Override public void onOnline(Computer c, TaskListener listener) throws IOException, InterruptedException {
            if (c instanceof SlaveComputer) {
                // TODO this does not work
                c.getChannel().call(new RemoteLogDumper(c.getDisplayName()));
            }
        }
        private static final class RemoteLogDumper extends MasterToSlaveCallable<Void, RuntimeException> {
            private final String name;
            private final TaskListener stderr = StreamTaskListener.fromStderr();
            RemoteLogDumper(String name) {
                this.name = name;
            }
            @Override public Void call() throws RuntimeException {
                new Thread(() -> {
                    StreamHandler consoleHandler = new StreamHandler() {
                        {
                            setOutputStream(stderr.getLogger());
                        }
                    };
                    consoleHandler.setLevel(Level.ALL);
                    consoleHandler.setFormatter(new Formatter() {
                        final Formatter delegate = new SimpleFormatter();
                        @Override public String format(LogRecord record) {
                            return delegate.format(record).replaceAll("(?m)^", "[" + name + "] ");
                        }
                    });
                    Logger logger = Logger.getLogger(PipelineBridge.class.getPackage().getName());
                    logger.setLevel(Level.FINER);
                    logger.addHandler(consoleHandler);
                }, "RemoteLogDumper").start();
                return null;
            }
        }
    }

    /**
     * {@link AWSCredentialsImpl} does permit access and secret key to be null.
     * But then it uses {@link InstanceProfileCredentialsProvider} which is not necessarily what we want:
     * that does not, for example, support {@code ~/.aws/credentials} plus {@code AWS_PROFILE} as in {@link DefaultAWSCredentialsProviderChain}.
     * Arguably that should be generalized in {@link AWSCredentialsImpl},
     * amending <a href="https://github.com/jenkinsci/aws-credentials-plugin/pull/20">PR 20</a>.
     */
    private static class AssumedRoleCreds extends BaseAmazonWebServicesCredentials {

        private final String role;

        AssumedRoleCreds(String role, CredentialsScope scope, String id, String description) {
            super(scope, id, description);
            this.role = role;
        }

        @Override public AWSCredentials getCredentials() {
            //AWSCredentials initialCredentials = DefaultAWSCredentialsProviderChain.getInstance().getCredentials();
            AssumeRoleResult r = AWSSecurityTokenServiceClientBuilder.defaultClient().assumeRole(new AssumeRoleRequest()
                    .withRoleArn(role)
                    .withRoleSessionName("PipelineBridgeTest"));
            return new BasicSessionCredentials(
                    r.getCredentials().getAccessKeyId(),
                    r.getCredentials().getSecretAccessKey(),
                    r.getCredentials().getSessionToken());
        }

        @Override public String getDisplayName() {
            return getId();
        }

        @Override public AWSCredentials getCredentials(String mfaToken) {
            throw new UnsupportedOperationException();
        }

        @Override public void refresh() {
            // no-op
        }

    }

    @Override protected LogStorage createStorage() throws Exception {
        return PipelineBridge.get().forIDs(LOG_STREAM_NAME, id);
    }

}
