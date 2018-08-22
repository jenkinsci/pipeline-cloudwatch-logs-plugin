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
import com.amazonaws.auth.AWSSessionCredentials;
import com.amazonaws.auth.AWSStaticCredentialsProvider;
import com.amazonaws.auth.BasicSessionCredentials;
import com.amazonaws.auth.DefaultAWSCredentialsProviderChain;
import com.amazonaws.services.logs.AWSLogs;
import com.amazonaws.services.logs.AWSLogsClientBuilder;
import com.amazonaws.services.logs.model.DescribeLogStreamsRequest;
import com.amazonaws.services.logs.model.DescribeLogStreamsResult;
import com.amazonaws.services.logs.model.InputLogEvent;
import com.amazonaws.services.logs.model.LogStream;
import com.amazonaws.services.logs.model.PutLogEventsRequest;
import com.amazonaws.services.logs.model.PutLogEventsResult;
import com.amazonaws.services.securitytoken.AWSSecurityTokenServiceClientBuilder;
import com.amazonaws.services.securitytoken.model.Credentials;
import com.amazonaws.services.securitytoken.model.GetFederationTokenRequest;
import com.amazonaws.services.securitytoken.model.GetFederationTokenResult;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import hudson.AbortException;
import hudson.ExtensionList;
import hudson.console.LineTransformationOutputStream;
import hudson.model.BuildListener;
import hudson.remoting.Channel;
import io.jenkins.plugins.aws.global_configuration.CredentialsAwsGlobalConfiguration;
import java.io.Closeable;
import java.io.IOException;
import java.io.PrintStream;
import java.io.UnsupportedEncodingException;
import java.util.Map;
import java.util.Objects;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.annotation.CheckForNull;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import net.sf.json.JSONObject;

/**
 * Sends Pipeline build log lines to CloudWatch Logs.
 */
final class CloudWatchSender implements BuildListener, Closeable {

    private static final Logger LOGGER = Logger.getLogger(CloudWatchSender.class.getName());

    private static final long serialVersionUID = 1;

    private final @Nonnull String logGroupName;
    private final @Nonnull String logStreamName;
    private final @Nonnull String buildId;
    private final @CheckForNull String nodeId;
    private transient @CheckForNull PrintStream logger;
    private transient AWSLogs client;
    private transient @CheckForNull String sequenceToken;
    private final @Nonnull String sender;
    @SuppressFBWarnings(value = "IS2_INCONSISTENT_SYNC", justification = "Only need to synchronize initialization; thereafter it remains set.")
    private transient @CheckForNull TimestampTracker timestampTracker;
    // TODO refactor all these plus sender into one struct:
    private final @CheckForNull String accessKeyId;
    private final @Nullable String secretAccessKey;
    private final @Nullable String sessionToken;
    private final @Nullable String region;

    CloudWatchSender(@Nonnull String logStreamName, @Nonnull String buildId, @CheckForNull String nodeId, @CheckForNull TimestampTracker timestampTracker) throws IOException {
        this(logGroupName(), logStreamName, buildId, nodeId, "master", timestampTracker, null, null, null, null);
    }

    private static String logGroupName() throws IOException {
        String logGroupName = ExtensionList.lookupSingleton(CloudWatchAwsGlobalConfiguration.class).getLogGroupName();
        if (logGroupName == null) {
            throw new AbortException("You must specify the CloudWatch log group name");
        }
        return logGroupName;
    }

    private CloudWatchSender(@Nonnull String logGroupName, @Nonnull String logStreamName, @Nonnull String buildId, @CheckForNull String nodeId, @Nonnull String sender, @CheckForNull TimestampTracker timestampTracker, @CheckForNull String accessKeyId, @Nullable String secretAccessKey, @Nullable String sessionToken, @Nullable String region) {
        this.logGroupName = logGroupName;
        this.logStreamName = Objects.requireNonNull(logStreamName);
        this.buildId = Objects.requireNonNull(buildId);
        this.nodeId = nodeId;
        this.sender = sender;
        this.timestampTracker = timestampTracker;
        this.accessKeyId = accessKeyId;
        this.secretAccessKey = secretAccessKey;
        this.sessionToken = sessionToken;
        this.region = region;
    }

    private Object writeReplace() throws IOException {
        AWSSecurityTokenServiceClientBuilder builder = AWSSecurityTokenServiceClientBuilder.standard();
        // TODO is this whole dance not abstractable? .sessionCredentials()?
        CredentialsAwsGlobalConfiguration credentialsConfig = CredentialsAwsGlobalConfiguration.get();
        String region = credentialsConfig.getRegion();
        if (region != null) {
            builder = builder.withRegion(region);
        }
        String credentialsId = credentialsConfig.getCredentialsId();
        if (credentialsId != null) {
            AWSStaticCredentialsProvider credentialsProvider = new AWSStaticCredentialsProvider(credentialsConfig.sessionCredentials(builder, region, credentialsId));
            builder.withCredentials(credentialsProvider);
        } else {
            builder.withCredentials(new DefaultAWSCredentialsProviderChain());
        }
        String agentName = Channel.current().getName();
        AWSCredentials masterCredentials = builder.getCredentials().getCredentials();
        String remotedAccessKeyId, remotedSecretAccessKey, remotedSessionToken;
        if (masterCredentials instanceof AWSSessionCredentials) {
            // otherwise would get AWSSecurityTokenServiceException: Cannot call GetFederationToken with session credentials
            // TODO try to use AssumeRule with a policy instead, if we have explicit credentials with a role; see AWSCredentialsImpl.getIamRoleArn/createAssumeRoleRequest
            // (assuming this can work without MFA every time)
            remotedAccessKeyId = masterCredentials.getAWSAccessKeyId();
            remotedSecretAccessKey = masterCredentials.getAWSSecretKey();
            remotedSessionToken = ((AWSSessionCredentials) masterCredentials).getSessionToken();
        } else {
            // TODO will need to rerun this on master side upon expiration of token:
            GetFederationTokenResult r = builder.build().getFederationToken(new GetFederationTokenRequest().
                    // TODO withPolicy restricting agent to PutLogEvents
                    // TODO uniquify name better; maybe generate random suffix?
                    withName((logStreamName + "-" + agentName).replaceAll("[^a-zA-Z0-9_=,.@-]+", "_").replaceFirst("(.{0,32}).*", "$1")));
            Credentials credentials = r.getCredentials();
            remotedAccessKeyId = credentials.getAccessKeyId();
            remotedSecretAccessKey = credentials.getSecretAccessKey();
            remotedSessionToken = credentials.getSessionToken();
        }
        return new CloudWatchSender(logGroupName, logStreamName, buildId, nodeId, agentName, /* do not currently bother to record events from agent side */null, remotedAccessKeyId, remotedSecretAccessKey, remotedSessionToken, region);
    }

    @Override
    public synchronized PrintStream getLogger() {
        if (logger == null) {
            AWSLogsClientBuilder builder;
            if (accessKeyId != null) {
                builder = AWSLogsClientBuilder.standard();
                if (region != null) {
                    builder = builder.withRegion(region);
                }
                builder.withCredentials(new AWSStaticCredentialsProvider(new BasicSessionCredentials(accessKeyId, secretAccessKey, sessionToken)));
            } else {
                try {
                    builder = ExtensionList.lookupSingleton(CloudWatchAwsGlobalConfiguration.class).getAWSLogsClientBuilder();
                } catch (IOException x) {
                    throw new RuntimeException(x);
                }
            }
            client = builder.build();
            if (timestampTracker == null) {
                timestampTracker = new TimestampTracker(); // need to serialize messages though we are not coördinating with CloudWatchRetriever on the master side
            }
            try {
                logger = new PrintStream(new CloudWatchOutputStream(), true, "UTF-8");
            } catch (UnsupportedEncodingException x) {
                throw new AssertionError(x);
            }
        }
        return logger;
    }

    @Override
    public synchronized void close() throws IOException {
        if (logger != null) {
            client.shutdown();
            logger = null;
            client = null;
        }
    }

    private synchronized String lastSequenceToken() {
        if (sequenceToken == null) {
            // TODO as per https://stackoverflow.com/a/32947579/12916 this is all wrong and we sometimes get InvalidSequenceTokenException between logging nodes
            // rather create a stream per job × node, for example jenkinsci/git-plugin/master@master or jenkinsci/git-plugin/master@node7
            // (avoiding actual node names since for elastic clouds they are liable to be random UUIDs, causing log stream pollution)
            // (and taking care to escape [:*@%] in job names using %XX URL encoding)
            // and then merge streams in CloudWatchRetriever using the interleaved flag after using DescribeLogStreams on jenkinsci/git-plugin/master@
            DescribeLogStreamsResult r = client.describeLogStreams(new DescribeLogStreamsRequest(logGroupName).withLogStreamNamePrefix(logStreamName));
            // TODO handle paging, in case we have a lot of similarly-named jobs
            for (LogStream ls : r.getLogStreams()) {
                if (ls.getLogStreamName().equals(logStreamName)) {
                    return sequenceToken = ls.getUploadSequenceToken();
                }
            }
            throw new IllegalStateException("could not find " + logStreamName);
        }
        return sequenceToken;
    }

    private class CloudWatchOutputStream extends LineTransformationOutputStream {
        
        @Override
        protected void eol(byte[] b, int len) throws IOException {
            Map<String, Object> data = ConsoleNotes.parse(b, len);
            data.put("build", buildId);
            if (nodeId != null) {
                data.put("node", nodeId);
            }
            data.put("sender", sender); // TODO remove once we have log stream per node
            assert timestampTracker != null : "getLogger which creates CloudWatchOutputStream initializes it";
            long now = timestampTracker.eventSent();
            data.put("timestamp", now); // TODO remove
            // TODO buffer messages and send asynchronously
            PutLogEventsResult result = client.putLogEvents(new PutLogEventsRequest().
                    withLogGroupName(logGroupName).
                    withLogStreamName(logStreamName).
                    withSequenceToken(lastSequenceToken()).
                    withLogEvents(new InputLogEvent().
                            withTimestamp(now).
                            withMessage(JSONObject.fromObject(data).toString())));
            LOGGER.log(Level.FINE, "result: {0}", result); // TODO how do we know if it was successful or not?
            synchronized (CloudWatchSender.this) {
                sequenceToken = result.getNextSequenceToken();
            }
            LOGGER.log(Level.FINER, "sent event @{0} from {1}/{2}#{3}", new Object[] {now, logStreamName, buildId, nodeId});
        }

    }

}
