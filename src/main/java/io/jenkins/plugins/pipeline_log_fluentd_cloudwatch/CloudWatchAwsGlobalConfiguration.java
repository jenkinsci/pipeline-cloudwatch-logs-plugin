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

import java.io.IOException;

import javax.annotation.Nonnull;

import org.apache.commons.lang.StringUtils;
import org.kohsuke.stapler.DataBoundSetter;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.interceptor.RequirePOST;

import com.amazonaws.auth.AWSStaticCredentialsProvider;
import com.amazonaws.auth.DefaultAWSCredentialsProviderChain;
import com.amazonaws.services.logs.AWSLogs;
import com.amazonaws.services.logs.AWSLogsClientBuilder;
import com.amazonaws.services.logs.model.FilterLogEventsRequest;

import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import hudson.model.Failure;
import hudson.util.FormValidation;
import io.jenkins.plugins.aws.global_configuration.AbstractAwsGlobalConfiguration;
import io.jenkins.plugins.aws.global_configuration.CredentialsAwsGlobalConfiguration;
import jenkins.model.Jenkins;
import org.jenkinsci.Symbol;

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

    @Nonnull
    @Override
    public String getDisplayName() {
        return "Amazon CloudWatch Logs settings";
    }

    public AWSLogsClientBuilder getAWSLogsClientBuilder() throws IOException {
        return getAWSLogsClientBuilder(CredentialsAwsGlobalConfiguration.get().getRegion());
    }

    /**
     *
     * @return an AWSLogsClientBuilder using the passed region
     * @throws IOException
     */
    private AWSLogsClientBuilder getAWSLogsClientBuilder(String region) throws IOException {
        AWSLogsClientBuilder builder = AWSLogsClientBuilder.standard()
                .withCredentials(new DefaultAWSCredentialsProviderChain());
        if (StringUtils.isNotBlank(region)) {
            builder = builder.withRegion(region);
        }
        if (builder.getCredentials() != null) {
            AWSStaticCredentialsProvider credentialsProvider = new AWSStaticCredentialsProvider(
                CredentialsAwsGlobalConfiguration.get().sessionCredentials(builder));
            return builder.withCredentials(credentialsProvider);
        } else {
            return builder;
        }
    }

    public FormValidation doCheckLogGroupName(@QueryParameter String logGroupName) {
        FormValidation ret = FormValidation.ok();
        if (StringUtils.isBlank(logGroupName)) {
            ret = FormValidation.warning("The log group name cannot be empty");
        }
        return ret;
    }

    @RequirePOST
    public FormValidation doValidate(@QueryParameter String logGroupName)
            throws IOException {
        Jenkins.get().checkPermission(Jenkins.ADMINISTER);

        AWSLogsClientBuilder builder = AWSLogsClientBuilder.standard()
                .withCredentials(new DefaultAWSCredentialsProviderChain());
        String region = CredentialsAwsGlobalConfiguration.get().getRegion();
        if (region != null) {
            builder = builder.withRegion(region);
        }

        FormValidation ret = FormValidation.ok("success");
        AWSLogs client;
        try {
            AWSStaticCredentialsProvider credentialsProvider = new AWSStaticCredentialsProvider(
                    CredentialsAwsGlobalConfiguration.get().sessionCredentials(builder));
            client = builder.withCredentials(credentialsProvider).build();
        } catch (Throwable t) {
            String msg = processExceptionMessage(t);
            ret = FormValidation.error("Unable to validate credentials: " + StringUtils.abbreviate(msg, 200));
            return ret;
        }

        try {
            FilterLogEventsRequest request = new FilterLogEventsRequest();
            request.setLogGroupName(logGroupName);
            client.filterLogEvents(request);
        } catch (Throwable t) {
            String msg = processExceptionMessage(t);
            ret = FormValidation.error(StringUtils.abbreviate(msg, 200));
        }
        return ret;
    }

}
