/*
 * The MIT License
 *
 * Copyright 2019 CloudBees, Inc.
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

import com.amazonaws.services.logs.AWSLogs;
import com.amazonaws.services.logs.model.DeleteLogStreamRequest;
import com.amazonaws.services.logs.model.ResourceNotFoundException;
import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.domains.Domain;
import hudson.ExtensionList;
import hudson.Functions;
import hudson.util.Secret;
import org.jenkinsci.plugins.plaincredentials.impl.StringCredentialsImpl;
import org.jenkinsci.plugins.workflow.cps.CpsFlowDefinition;
import org.jenkinsci.plugins.workflow.job.WorkflowJob;
import org.junit.ClassRule;
import org.junit.Test;
import static org.junit.Assume.assumeFalse;
import org.junit.Before;
import org.junit.Rule;
import org.jvnet.hudson.test.BuildWatcher;
import org.jvnet.hudson.test.Issue;
import org.jvnet.hudson.test.JenkinsRule;

public class IntegrationTest {

    @ClassRule public static BuildWatcher buildWatcher = new BuildWatcher();

    @Rule public JenkinsRule r = new JenkinsRule();

    @Before public void setUp() throws Exception {
        PipelineBridgeTest.globalConfiguration();
        CloudWatchAwsGlobalConfiguration config = ExtensionList.lookupSingleton(CloudWatchAwsGlobalConfiguration.class);
        AWSLogs client = config.getAWSLogsClientBuilder().build();
        for (String node : new String[] {"master", "agent1"}) {
            try {
                client.deleteLogStream(new DeleteLogStreamRequest(config.getLogGroupName(), "p@" + node));
            } catch (ResourceNotFoundException x) {
                // OK
            }
        }
    }

    @Issue("https://github.com/jenkinsci/workflow-durable-task-step-plugin/pull/112")
    @Test public void missingNewline() throws Exception {
        assumeFalse(Functions.isWindows());
        CredentialsProvider.lookupStores(r.jenkins).iterator().next().addCredentials(Domain.global(), new StringCredentialsImpl(CredentialsScope.GLOBAL, "creds", null, Secret.fromString("s3cr3t")));
        r.createSlave("remote", null, null);
        WorkflowJob p = r.jenkins.createProject(WorkflowJob.class, "p");
        p.setDefinition(new CpsFlowDefinition(
            "node('remote') {\n" +
            "  withCredentials([string(variable: 'UNUSED', credentialsId: 'creds')]) {\n" +
            "    sh 'set +x; printf \"missing final newline\"'\n" +
            "  }\n" +
            "}", true));
        r.assertLogContains("missing final newline", r.buildAndAssertSuccess(p));
    }

}
