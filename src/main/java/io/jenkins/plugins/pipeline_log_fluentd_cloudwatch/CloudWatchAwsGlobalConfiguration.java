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
import java.util.Collections;
import java.util.Map;

import javax.annotation.Nonnull;

import org.apache.commons.lang.StringUtils;
import org.jenkinsci.Symbol;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.NoExternalUse;
import org.kohsuke.stapler.DataBoundSetter;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.interceptor.RequirePOST;
import org.komamitsu.fluency.EventTime;
import org.komamitsu.fluency.Fluency;
import org.komamitsu.fluency.buffer.PackedForwardBuffer;
import org.komamitsu.fluency.flusher.AsyncFlusher;
import org.komamitsu.fluency.flusher.SyncFlusher;
import org.komamitsu.fluency.sender.RetryableSender;
import org.komamitsu.fluency.sender.TCPSender;
import org.komamitsu.fluency.sender.retry.ExponentialBackOffRetryStrategy;

import com.amazonaws.auth.AWSStaticCredentialsProvider;
import com.amazonaws.auth.DefaultAWSCredentialsProviderChain;
import com.amazonaws.services.logs.AWSLogs;
import com.amazonaws.services.logs.AWSLogsClientBuilder;
import com.amazonaws.services.logs.model.FilterLogEventsRequest;

import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import hudson.Util;
import hudson.model.Failure;
import hudson.util.FormValidation;
import io.jenkins.plugins.aws.global_configuration.AbstractAwsGlobalConfiguration;
import io.jenkins.plugins.aws.global_configuration.CredentialsAwsGlobalConfiguration;
import jenkins.model.Jenkins;

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

    /**
     * Fluentd host.
     */
    private String fluentdHost;

    /**
     * Fluentd port.
     */
    private int fluentdPort;

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

    public String getFluentdHost() {
        return fluentdHost;
    }

    @DataBoundSetter
    public void setFluentdHost(String fluentdHost) {
        this.fluentdHost = fluentdHost;
        save();
    }

    public int getFluentdPort() {
        return fluentdPort;
    }

    /**
     * @return the fluentd host calculated from configured values, environment variable
     *         <code>FLUENTD_SERVICE_HOST</code> and default <code>localhost</code>
     */
    String computeFluentdHost() {
        return computeFluentdHost(getFluentdHost());
    }

    /**
     * @return the fluentd port calculated from configured values, environment variable
     *         <code>FLUENTD_SERVICE_PORT_TCP</code> and default <code>24224</code> port
     */
    int computeFluentdPort() {
        return computeFluentdPort(getFluentdPort());
    }

    private static String computeFluentdHost(String fluentdHost) {
        String host = fluentdHost != null ? fluentdHost : System.getenv("FLUENTD_SERVICE_HOST");
        return host != null ? host : "localhost";
    }

    private static int computeFluentdPort(int fluentdPort) {
        if (fluentdPort != 0) {
            return fluentdPort;
        }
        String port = System.getenv("FLUENTD_SERVICE_PORT_TCP");
        return port == null ? 24224 : Integer.parseInt(port);
    }

    @DataBoundSetter
    public void setFluentdPort(int fluentdPort) {
        this.fluentdPort = fluentdPort;
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
        return getAWSLogsClientBuilder(CredentialsAwsGlobalConfiguration.get().getRegion(),
                CredentialsAwsGlobalConfiguration.get().getCredentialsId());
    }

    /**
     *
     * @return an AWSLogsClientBuilder using the passed region
     * @throws IOException
     */
    @Restricted(NoExternalUse.class)
    AWSLogsClientBuilder getAWSLogsClientBuilder(String region, String credentialsId) throws IOException {
        AWSLogsClientBuilder builder = AWSLogsClientBuilder.standard();
        if (region != null) {
            builder = builder.withRegion(region);
        }
        if (credentialsId != null) {
            AWSStaticCredentialsProvider credentialsProvider = new AWSStaticCredentialsProvider(
                    CredentialsAwsGlobalConfiguration.get().sessionCredentials(builder, region, credentialsId));
            return builder.withCredentials(credentialsProvider);
        } else {
            return builder.withCredentials(new DefaultAWSCredentialsProviderChain());
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
    public FormValidation doValidate(@QueryParameter String logGroupName, @QueryParameter String fluentdHost,
            @QueryParameter int fluentdPort, @QueryParameter String region, @QueryParameter String credentialsId)
            throws IOException {
        Jenkins.get().checkPermission(Jenkins.ADMINISTER);
        return validate(logGroupName, Util.fixEmptyAndTrim(fluentdHost), fluentdPort, Util.fixEmptyAndTrim(region),
                Util.fixEmptyAndTrim(credentialsId));
    }

    @Restricted(NoExternalUse.class)
    FormValidation validate(String logGroupName, String fluentdHost, int fluentdPort, String region,
            String credentialsId) throws IOException {
        FormValidation ret = FormValidation.ok("success");
        AWSLogs client;
        try {
            AWSLogsClientBuilder builder = getAWSLogsClientBuilder(region, credentialsId);
            client = builder.build();
        } catch (Throwable t) {
            String msg = processExceptionMessage(t);
            ret = FormValidation.error("Unable to validate credentials: " + StringUtils.abbreviate(msg, 200));
            return ret;
        }

        try {
            validateCloudWatch(client, logGroupName);
        } catch (Throwable t) {
            String msg = processExceptionMessage(t);
            ret = FormValidation.error("Unable to validate log group name: " + StringUtils.abbreviate(msg, 200));
            return ret;
        }

        String host = computeFluentdHost(fluentdHost);
        int port = computeFluentdPort(fluentdPort);
        try {
            validateFluentd(host, port);
        } catch (Throwable t) {
            String msg = processExceptionMessage(t);
            ret = FormValidation.error(String.format("Unable to validate fluentd host and port (%s:%d): %s", host, port,
                    StringUtils.abbreviate(msg, 200)));
            return ret;
        }
        return ret;
    }

    void validateCloudWatch(AWSLogs client, String logGroupName) {
        FilterLogEventsRequest request = new FilterLogEventsRequest();
        request.setLogGroupName(logGroupName);
        client.filterLogEvents(request);
    }

    void validateFluentd(String fluentdHost, int fluentdPort) throws IOException {
        // configure a sync fluentd logger so we can catch the exceptions when validating
        SyncFlusher.Config flusherConfig = new SyncFlusher.Config().setFlushIntervalMillis(1000);
        TCPSender sender = new TCPSender.Config().setHost(fluentdHost).setPort(fluentdPort).createInstance();
        Fluency logger = new Fluency.Builder(sender).setFlusherConfig(flusherConfig).build();

        long now = System.currentTimeMillis();
        logger.emit("validate", EventTime.fromEpochMilli(now), Collections.emptyMap());
        logger.flush();
    }
}
