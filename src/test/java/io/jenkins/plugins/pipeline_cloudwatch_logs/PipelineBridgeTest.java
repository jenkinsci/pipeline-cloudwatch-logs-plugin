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

package io.jenkins.plugins.pipeline_cloudwatch_logs;

import com.cloudbees.jenkins.plugins.awscredentials.AWSCredentialsImpl;
import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.SystemCredentialsProvider;
import hudson.ExtensionList;
import hudson.util.FormValidation;
import io.jenkins.plugins.aws.global_configuration.CredentialsAwsGlobalConfiguration;
import java.util.Collections;
import java.util.Map;
import java.util.UUID;
import java.util.logging.Level;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import org.jenkinsci.plugins.workflow.log.LogStorage;
import org.jenkinsci.plugins.workflow.log.LogStorageTestBase;
import org.junit.jupiter.api.BeforeEach;
import org.jvnet.hudson.test.LogRecorder;

class PipelineBridgeTest extends LogStorageTestBase {

    private static final String LOG_STREAM_NAME = "PipelineBridgeTest";

    @SuppressWarnings("unused")
    private final LogRecorder logging = new LogRecorder().recordPackage(PipelineBridge.class, Level.FINER);
    private String id;

    static void globalConfiguration() {
        String logGroupName = System.getenv("CLOUDWATCH_LOG_GROUP_NAME");
        assumeTrue(logGroupName != null, "must define $CLOUDWATCH_LOG_GROUP_NAME");
        String role = System.getenv("AWS_ROLE");
        String credentialsId = null;
        if (role != null) {
            credentialsId = "aws";
            SystemCredentialsProvider.getInstance().getCredentials().add(new AWSCredentialsImpl(CredentialsScope.GLOBAL, credentialsId, null, null, null, role, null));
            CredentialsAwsGlobalConfiguration.get().setCredentialsId(credentialsId);
        }
        CloudWatchAwsGlobalConfiguration configuration = ExtensionList.lookupSingleton(CloudWatchAwsGlobalConfiguration.class);
        FormValidation logGroupNameValidation = configuration.validate(logGroupName, null, credentialsId, false);
        assumeTrue(logGroupNameValidation.kind == FormValidation.Kind.OK, logGroupNameValidation.toString());
        configuration.setLogGroupName(logGroupName);
    }

    @BeforeEach
    void setUp() {
        globalConfiguration();
        id = UUID.randomUUID().toString();
    }

    @Override
    protected LogStorage createStorage() {
        return PipelineBridge.get().forIDs(LOG_STREAM_NAME, id);
    }

    @Override
    protected Map<String, Level> agentLoggers() {
        return Collections.singletonMap(PipelineBridge.class.getPackage().getName(), Level.FINER);
    }
}
