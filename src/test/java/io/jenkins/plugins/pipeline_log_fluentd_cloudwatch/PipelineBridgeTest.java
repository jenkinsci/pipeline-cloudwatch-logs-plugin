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
import hudson.util.FormValidation;
import io.jenkins.plugins.aws.global_configuration.CredentialsAwsGlobalConfiguration;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Level;
import static org.hamcrest.Matchers.*;
import org.jenkinsci.plugins.workflow.log.LogStorage;
import org.jenkinsci.plugins.workflow.log.LogStorageTestBase;
import static org.junit.Assume.*;
import org.junit.Before;
import org.junit.Rule;
import org.jvnet.hudson.test.LoggerRule;

public class PipelineBridgeTest extends LogStorageTestBase {

    @Rule public LoggerRule logging = new LoggerRule().recordPackage(PipelineBridge.class, Level.FINER);
    private Map<String, TimestampTracker> timestampTrackers;
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
        timestampTrackers = new ConcurrentHashMap<>();
        id = UUID.randomUUID().toString();
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
        return new PipelineBridge.LogStorageImpl("PipelineBridgeTest", id, timestampTrackers);
    }

}
