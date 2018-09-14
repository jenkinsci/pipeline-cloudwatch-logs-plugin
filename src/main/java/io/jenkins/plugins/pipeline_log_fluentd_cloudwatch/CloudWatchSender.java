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

import com.amazonaws.SdkBaseException;
import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.auth.AWSCredentialsProvider;
import com.amazonaws.auth.AWSSessionCredentials;
import com.amazonaws.auth.AWSStaticCredentialsProvider;
import com.amazonaws.auth.BasicSessionCredentials;
import com.amazonaws.services.logs.AWSLogs;
import com.amazonaws.services.logs.AWSLogsClientBuilder;
import com.amazonaws.services.logs.model.CreateLogStreamRequest;
import com.amazonaws.services.logs.model.DescribeLogStreamsRequest;
import com.amazonaws.services.logs.model.DescribeLogStreamsResult;
import com.amazonaws.services.logs.model.InputLogEvent;
import com.amazonaws.services.logs.model.InvalidSequenceTokenException;
import com.amazonaws.services.logs.model.LogStream;
import com.amazonaws.services.logs.model.PutLogEventsRequest;
import com.amazonaws.services.logs.model.PutLogEventsResult;
import com.amazonaws.services.logs.model.RejectedLogEventsInfo;
import com.amazonaws.services.securitytoken.AWSSecurityTokenServiceClientBuilder;
import com.amazonaws.services.securitytoken.model.AssumeRoleRequest;
import com.amazonaws.services.securitytoken.model.AssumeRoleResult;
import com.amazonaws.services.securitytoken.model.Credentials;
import com.amazonaws.services.securitytoken.model.GetFederationTokenRequest;
import com.amazonaws.services.securitytoken.model.GetFederationTokenResult;
import com.cloudbees.jenkins.plugins.awscredentials.AmazonWebServicesCredentials;
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
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.annotation.CheckForNull;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import jenkins.util.JenkinsJVM;
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
    @SuppressFBWarnings(value = "IS2_INCONSISTENT_SYNC", justification = "Set to a single value so long as the logger remains open.")
    private final @Nonnull String sender;
    @SuppressFBWarnings(value = "IS2_INCONSISTENT_SYNC", justification = "Only need to synchronize initialization; thereafter it remains set.")
    private transient @CheckForNull TimestampTracker timestampTracker;
    // TODO refactor all these plus sender into one struct:
    private final @CheckForNull String accessKeyId;
    private final @Nullable String secretAccessKey;
    private final @Nullable String sessionToken;
    private final @Nullable String region;
    private final @Nonnull BlockingQueue<InputLogEvent> events = new ArrayBlockingQueue<>(10_000); // https://docs.aws.amazon.com/AmazonCloudWatchLogs/latest/APIReference/API_PutLogEvents.html max batch size

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
        CredentialsAwsGlobalConfiguration credentialsConfig = CredentialsAwsGlobalConfiguration.get();
        String region = credentialsConfig.getRegion();
        if (region != null) {
            builder = builder.withRegion(region);
        }
        AmazonWebServicesCredentials jenkinsCredentials = credentialsConfig.getCredentials();
        if (jenkinsCredentials != null) {
            AWSStaticCredentialsProvider credentialsProvider = new AWSStaticCredentialsProvider(jenkinsCredentials.getCredentials());
            builder.withCredentials(credentialsProvider);
        }
        String agentName = Channel.current().getName();
        AWSCredentialsProvider credentialsProvider = builder.getCredentials();
        AWSCredentials masterCredentials = credentialsProvider != null ? credentialsProvider.getCredentials() : null;
        String remotedAccessKeyId, remotedSecretAccessKey, remotedSessionToken;
        if (masterCredentials instanceof AWSSessionCredentials) {
            // otherwise would just throw AWSSecurityTokenServiceException: Cannot call GetFederationToken with session credentials
            // TODO just check for ((AWSCredentialsImpl) jenkinsCredentials).getIamRoleArn() if that is fixed to use the default provider chain
            String role = System.getenv("AWS_ROLE");
            if (role != null) {
                // TODO would be cleaner if AmazonWebServicesCredentials had a getCredentials overload taking a policy
                builder = AWSSecurityTokenServiceClientBuilder.standard();
                if (region != null) {
                    builder = builder.withRegion(region);
                }
                // TODO will need to rerun this on master side upon expiration of token:
                AssumeRoleResult r = builder.build().assumeRole(new AssumeRoleRequest().
                        withRoleArn(role).
                        withRoleSessionName("CloudWatchSender"). // TODO does this need to be unique?
                        withPolicy(policy()));
                Credentials credentials = r.getCredentials();
                remotedAccessKeyId = credentials.getAccessKeyId();
                remotedSecretAccessKey = credentials.getSecretAccessKey();
                remotedSessionToken = credentials.getSessionToken();
                LOGGER.log(Level.FINE, "AssumeRole succeeded; using {0}", remotedAccessKeyId);
            } else {
                remotedAccessKeyId = masterCredentials.getAWSAccessKeyId();
                remotedSecretAccessKey = masterCredentials.getAWSSecretKey();
                remotedSessionToken = ((AWSSessionCredentials) masterCredentials).getSessionToken();
                // TODO move warnings like these to CloudWatchAwsGlobalConfiguration.validate
                LOGGER.log(Level.WARNING, "Giving up on limiting session credentials to a policy; using {0} as is", remotedAccessKeyId);
            }
        } else if (masterCredentials == null) {
            remotedAccessKeyId = null;
            remotedSecretAccessKey = null;
            remotedSessionToken = null;
            LOGGER.log(Level.WARNING, "No AWS credentials to be found, giving up on limiting to a policy");
        } else {
            // TODO will need to rerun this on master side upon expiration of token:
            GetFederationTokenResult r = builder.build().getFederationToken(new GetFederationTokenRequest().
                    withName("CloudWatchSender"). // TODO as above?
                    withPolicy(policy()));
            Credentials credentials = r.getCredentials();
            remotedAccessKeyId = credentials.getAccessKeyId();
            remotedSecretAccessKey = credentials.getSecretAccessKey();
            remotedSessionToken = credentials.getSessionToken();
            LOGGER.log(Level.FINE, "GetFederationToken succeeded; using {0}", remotedAccessKeyId);
        }
        return new CloudWatchSender(logGroupName, logStreamName, buildId, nodeId, agentName, /* do not currently bother to record events from agent side */null, remotedAccessKeyId, remotedSecretAccessKey, remotedSessionToken, region);
    }

    /** @see <a href="https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/iam-access-control-overview-cwl.html">Reference</a> */
    private String policy() {
        return "{\"Version\": \"2012-10-17\", \"Statement\": [" +
                "{\"Effect\": \"Allow\", \"Action\": [\"logs:PutLogEvents\"], \"Resource\": [\"arn:aws:logs:*:*:log-group:" + logGroupName + ":log-stream:" + logStreamName + "\"]}, " +
                "{\"Effect\": \"Allow\", \"Action\": [\"logs:DescribeLogStreams\"], \"Resource\": [\"arn:aws:logs:*:*:log-group:" + logGroupName + ":log-stream:*\"]}" + // TODO delete
                "]}";
    }

    @Override
    public synchronized PrintStream getLogger() {
        if (logger == null) {
            if (timestampTracker == null) {
                timestampTracker = new TimestampTracker(); // need to serialize messages though we are not coördinating with CloudWatchRetriever on the master side
            }
            new Thread(this::process, "CloudWatchSender:" + logGroupName + ":" + logStreamName).start(); // TODO share threads between loggers using poll methods, or use NIO methods
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
            LOGGER.log(Level.FINE, "closing {0}/{1}#{2}", new Object[] {logStreamName, buildId, nodeId});
            logger = null;
        }
    }

    private void process() {
        AWSLogsClientBuilder builder;
        if (accessKeyId != null) {
            builder = AWSLogsClientBuilder.standard();
            if (region != null) {
                builder = builder.withRegion(region);
            }
            builder.withCredentials(new AWSStaticCredentialsProvider(new BasicSessionCredentials(accessKeyId, secretAccessKey, sessionToken)));
        } else if (JenkinsJVM.isJenkinsJVM()) {
            try {
                builder = ExtensionList.lookupSingleton(CloudWatchAwsGlobalConfiguration.class).getAWSLogsClientBuilder();
            } catch (IOException x) {
                throw new RuntimeException(x);
            }
        } else {
            try {
                builder = CloudWatchAwsGlobalConfiguration.getAWSLogsClientBuilder(region, null);
            } catch (IOException x) {
                throw new RuntimeException(x);
            }
        }
        AWSLogs client = builder.build();
        String sequenceToken = null;
        // TODO as per https://stackoverflow.com/a/32947579/12916 this is all wrong and we sometimes get InvalidSequenceTokenException between logging nodes
        // rather create a stream per job × node, for example jenkinsci/git-plugin/master@master or jenkinsci/git-plugin/master@node7
        // (avoiding actual node names since for elastic clouds they are liable to be random UUIDs, causing log stream pollution)
        // (and taking care to escape [:*@%] in job names using %XX URL encoding)
        // and then merge streams in CloudWatchRetriever using the interleaved flag after using DescribeLogStreams on jenkinsci/git-plugin/master@
        DescribeLogStreamsResult r = client.describeLogStreams(new DescribeLogStreamsRequest(logGroupName).withLogStreamNamePrefix(logStreamName));
        // TODO handle paging, in case we have a lot of similarly-named jobs
        for (LogStream ls : r.getLogStreams()) {
            if (ls.getLogStreamName().equals(logStreamName)) {
                sequenceToken = ls.getUploadSequenceToken();
                break;
            }
        }
        if (sequenceToken == null) {
            // First-time project.
            client.createLogStream(new CreateLogStreamRequest(logGroupName, logStreamName));
        }
        MAIN: while (true) {
            List<InputLogEvent> processing = new ArrayList<>();
            if (events.drainTo(processing) == 0) {
                LOGGER.log(Level.FINEST, "waiting for events from {0}/{1}#{2}", new Object[] {logStreamName, buildId, nodeId});
                try {
                    Thread.sleep(200); // https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/cloudwatch_limits_cwl.html 5 reqs/s/stream
                } catch (InterruptedException x) {
                    LOGGER.log(Level.WARNING, null, x);
                }
                continue;
            }
            // TODO as per https://docs.aws.amazon.com/AmazonCloudWatchLogs/latest/APIReference/API_PutLogEvents.html verify that total size <1Mb (no documented error class for excess size?)
            assert !processing.isEmpty();
            while (true) {
                try {
                    PutLogEventsResult result = client.putLogEvents(new PutLogEventsRequest().
                            withLogGroupName(logGroupName).
                            withLogStreamName(logStreamName).
                            withSequenceToken(sequenceToken).
                            withLogEvents(processing));
                    sequenceToken = result.getNextSequenceToken();
                    RejectedLogEventsInfo problems = result.getRejectedLogEventsInfo();
                    if (problems != null) {
                        LOGGER.log(Level.WARNING, "Rejected some log events: {0}", problems);
                    }
                    break;
                } catch (InvalidSequenceTokenException x) {
                    LOGGER.fine("Recovering from InvalidSequenceTokenException");
                    sequenceToken = x.getExpectedSequenceToken();
                    // and retry
                } catch (SdkBaseException x) {
                    // E.g.: AWSLogsException: Rate exceeded (Service: AWSLogs; Status Code: 400; Error Code: ThrottlingException; Request ID: …)
                    LOGGER.log(Level.FINE, "could throw up IOException to be swallowed by PrintStream or sent to master by DurableTaskStep but instead retrying", x);
                    try {
                        Thread.sleep(1000); // TODO exponential backoff, and limit number of retries before giving up
                    } catch (InterruptedException x2) {
                        LOGGER.log(Level.WARNING, null, x2);
                    }
                } catch (RuntimeException x) {
                    LOGGER.log(Level.WARNING, "giving up on this logger", x);
                    synchronized (this) {
                        logger = null;
                    }
                    break MAIN;
                }
            }
            LOGGER.log(Level.FINER, "sent {0} events @{1} from {2}/{3}#{4}", new Object[] {processing.size(), processing.get(processing.size() - 1).getTimestamp(), logStreamName, buildId, nodeId});
            synchronized (this) {
                if (logger == null && events.isEmpty()) {
                    LOGGER.log(Level.FINER, "{0}/{1}#{2} has been closed", new Object[] {logStreamName, buildId, nodeId});
                    break;
                }
            }
        }
        client.shutdown();
    }

    private class CloudWatchOutputStream extends LineTransformationOutputStream {
        
        @Override
        protected void eol(byte[] b, int len) throws IOException {
            synchronized (CloudWatchSender.this) {
                if (logger == null) {
                    LOGGER.log(Level.FINER, "refusing to schedule event from closed or broken {0}/{1}#{2}", new Object[] {logStreamName, buildId, nodeId});
                    return;
                }
            }
            Map<String, Object> data = ConsoleNotes.parse(b, len);
            data.put("build", buildId);
            if (nodeId != null) {
                data.put("node", nodeId);
            }
            data.put("sender", sender); // TODO remove once we have log stream per node
            assert timestampTracker != null : "getLogger which creates CloudWatchOutputStream initializes it";
            long now = timestampTracker.eventSent(); // when the logger prints something, *not* when we send it to CWL
            data.put("timestamp", now); // TODO remove
            try {
                if (events.offer(new InputLogEvent().
                        withTimestamp(now).
                        withMessage(JSONObject.fromObject(data).toString()),
                        1, TimeUnit.MINUTES)) {
                    LOGGER.log(Level.FINER, "scheduled event @{0} from {1}/{2}#{3}", new Object[] {now, logStreamName, buildId, nodeId});
                } else {
                    LOGGER.warning("Message buffer full, giving up");
                }
            } catch (InterruptedException x) {
                LOGGER.log(Level.WARNING, "stopped waiting to send a message", x);
            }
        }

    }

}
