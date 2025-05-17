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

import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import hudson.Util;
import hudson.model.Failure;
import hudson.util.FormValidation;
import io.jenkins.plugins.aws.global_configuration.AbstractAwsGlobalConfiguration;
import io.jenkins.plugins.aws.global_configuration.CredentialsAwsGlobalConfiguration;
import java.io.IOException;
import jenkins.model.Jenkins;
import org.apache.commons.lang.StringUtils;
import org.jenkinsci.Symbol;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.NoExternalUse;
import org.kohsuke.stapler.DataBoundSetter;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.interceptor.RequirePOST;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.cloudwatchlogs.CloudWatchLogsClient;

/**
 * Store the AWS configuration to save it on a separate file
 */
@Symbol("cloudWatchLogs")
@Extension
public class CloudWatchAwsGlobalConfiguration extends AbstractAwsGlobalConfiguration {

    /**
     * Name of the CloudWatch log group.
     */
    private String logGroupName;

    public CloudWatchAwsGlobalConfiguration() {
        load();
    }

    /**
     * Testing only
     */
    CloudWatchAwsGlobalConfiguration(boolean test) {
    }

    public String getLogGroupName() {
        return logGroupName;
    }

    @DataBoundSetter
    public void setLogGroupName(String logGroupName) {
        this.logGroupName = logGroupName;
        checkValue(doCheckLogGroupName(logGroupName));
        save();
    }

    private void checkValue(@NonNull FormValidation formValidation) {
        if (formValidation.kind == FormValidation.Kind.ERROR) {
            throw new Failure(formValidation.getMessage());
        }
    }

    @NonNull
    @Override
    public String getDisplayName() {
        return "Amazon CloudWatch Logs settings";
    }

    public CloudWatchLogsClient getCloudWatchLogsClient() throws IOException {
        return getCloudWatchLogsClient(CredentialsAwsGlobalConfiguration.get().getRegion(),
                CredentialsAwsGlobalConfiguration.get().getCredentialsId());
    }

    /**
     *
     * @return an AWSLogsClientBuilder using the passed region
     */
    @Restricted(NoExternalUse.class)
    static CloudWatchLogsClient getCloudWatchLogsClient(String region, String credentialsId) {
        var builder = CloudWatchLogsClient.builder();
        if (region != null) {
            builder = builder.region(Region.of(region));
        }
        if (credentialsId != null) {
            var c = CredentialsAwsGlobalConfiguration.get().getCredentials(credentialsId);
            if (c != null) {
                builder.credentialsProvider(c);
            }
        }
        return builder.build();
    }

    public FormValidation doCheckLogGroupName(@QueryParameter String logGroupName) {
        FormValidation ret = FormValidation.ok();
        if (StringUtils.isBlank(logGroupName)) {
            ret = FormValidation.warning("The log group name cannot be empty");
        }
        return ret;
    }

    @RequirePOST
    public FormValidation doValidate(@QueryParameter String logGroupName, @QueryParameter String region,
            @QueryParameter String credentialsId) {
        Jenkins.get().checkPermission(Jenkins.ADMINISTER);
        return validate(logGroupName, Util.fixEmptyAndTrim(region), Util.fixEmptyAndTrim(credentialsId), true);
    }

    @Restricted(NoExternalUse.class)
    FormValidation validate(String logGroupName, String region, String credentialsId, boolean abbreviate) {
        CloudWatchLogsClient client;
        try {
            client = getCloudWatchLogsClient(region, credentialsId);
        } catch (Exception x) {
            String msg = processExceptionMessage(x);
            return FormValidation.error("Unable to validate credentials: " + (abbreviate ? StringUtils.abbreviate(msg, 200) : msg));
        }

        try {
            filter(client, logGroupName);
            // TODO should also check DescribeLogStreams, and perhaps even CreateLogStream and PutLogEvents, to ensure roles are correct
        } catch (Exception x) {
            String msg = processExceptionMessage(x);
            return FormValidation.error(StringUtils.abbreviate(msg, 200));
        }
        try {
            String message = LogStreamState.validate(logGroupName);
            if (message != null) {
                return FormValidation.warning(message);
            }
        } catch (Exception x) {
            String msg = processExceptionMessage(x);
            return FormValidation.error("Unable to simulate policy restriction: " + (abbreviate ? StringUtils.abbreviate(msg, 200) : msg));
        }
        return FormValidation.ok("success");
    }

    @Restricted(NoExternalUse.class)
    protected void filter(CloudWatchLogsClient client, String logGroupName) {
        // TODO this returns a ton of data, when all we care about is that the request does not fail; filter it down to just a few results
        client.filterLogEvents(b -> b.logGroupName(logGroupName));
    }

}
