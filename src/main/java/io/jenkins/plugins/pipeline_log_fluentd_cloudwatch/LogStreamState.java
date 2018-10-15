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
import hudson.ExtensionList;
import hudson.remoting.Channel;
import io.jenkins.plugins.aws.global_configuration.CredentialsAwsGlobalConfiguration;
import java.io.IOException;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.annotation.CheckForNull;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import jenkins.util.JenkinsJVM;
import org.jenkinsci.remoting.SerializableOnlyOverRemoting;

/**
 * What is happening in a given log stream.
 * This will be specific to a job and a node JVM, but not to a build.
 */
abstract class LogStreamState {

    private static final Logger LOGGER = Logger.getLogger(LogStreamState.class.getName());

    private static final Map<String, LogStreamState> states = new ConcurrentHashMap<>();

    static LogStreamState onMaster(String logGroupName, String logStreamNameBase) {
        return states.computeIfAbsent(logGroupName + "#" + logStreamNameBase, k -> new MasterState(logGroupName, logStreamNameBase));
    }

    static LogStreamState onAgent(String logGroupName, String logStreamNameBase, MasterCalls masterCalls) {
        return states.computeIfAbsent(logGroupName + "#" + logStreamNameBase, k -> new AgentState(logGroupName, logStreamNameBase, masterCalls));
    }

    protected final String logGroupName;
    protected final String logStreamNameBase;
    private final @Nonnull BlockingQueue<InputLogEvent> events = new ArrayBlockingQueue<>(10_000); // https://docs.aws.amazon.com/AmazonCloudWatchLogs/latest/APIReference/API_PutLogEvents.html max batch size

    private LogStreamState(String logGroupName, String logStreamNameBase) {
        this.logGroupName = logGroupName;
        this.logStreamNameBase = logStreamNameBase;
    }

    private static final class MasterState extends LogStreamState implements MasterCalls {

        private @CheckForNull AWSLogs client;
        private final Set<String> agentLogStreamNames = new HashSet<>();

        private MasterState(String logGroupName, String logStreamNameBase) {
            super(logGroupName, logStreamNameBase);
            JenkinsJVM.checkJenkinsJVM();
        }

        @Override protected StateSupplier remote() {
            return new StateSupplier(logGroupName, logStreamNameBase, Channel.currentOrFail().export(MasterCalls.class, this));
        }

        @Override protected synchronized AWSLogs client() throws IOException {
            if (client == null) {
                client = ExtensionList.lookupSingleton(CloudWatchAwsGlobalConfiguration.class).getAWSLogsClientBuilder().build();
            }
            return client;
        }

        @Override protected String logStreamName() {
            return logStreamNameBase + "@master";
        }

        @Override protected void ensureRunning() throws IOException {
            boolean starting;
            synchronized (this) {
                starting = client == null;
            }
            if (starting) {
                create(logStreamName());
                schedule();
            }
        }

        @Override protected synchronized void shutDown() {
            if (client != null) {
                client.shutdown();
                client = null;
            }
        }

        private void create(String logStreamName) throws IOException {
            AWSLogs currentClient = client();
            DescribeLogStreamsResult r = currentClient.describeLogStreams(new DescribeLogStreamsRequest(logGroupName).withLogStreamNamePrefix(logStreamName));
            boolean found = false;
            // TODO handle paging, in case we have a lot of similarly-named jobs
            for (LogStream ls : r.getLogStreams()) {
                if (ls.getLogStreamName().equals(logStreamName)) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                // First-time project.
                LOGGER.log(Level.FINE, "Creating {0}", logStreamName);
                currentClient.createLogStream(new CreateLogStreamRequest(logGroupName, logStreamName));
            }
        }

        @Override public Auth authenticate() throws IOException {
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
            AWSCredentialsProvider credentialsProvider = builder.getCredentials();
            AWSCredentials masterCredentials = credentialsProvider != null ? credentialsProvider.getCredentials() : null;
            String remotedAccessKeyId, remotedSecretAccessKey, remotedSessionToken;
            String agentLogStreamName;
            synchronized (agentLogStreamNames) {
                for (int i = 1; ; i++) {
                    String candidate = logStreamNameBase + "@agent" + i;
                    if (agentLogStreamNames.add(candidate)) {
                        agentLogStreamName = candidate;
                        break;
                    }
                }
            }
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
                    AssumeRoleResult r = builder.build().assumeRole(new AssumeRoleRequest().
                            withRoleArn(role).
                            withRoleSessionName("CloudWatchSender"). // TODO does this need to be unique?
                            withPolicy(policy(agentLogStreamName)));
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
                GetFederationTokenResult r = builder.build().getFederationToken(new GetFederationTokenRequest().
                        withName("CloudWatchSender"). // TODO as above?
                        withPolicy(policy(agentLogStreamName)));
                Credentials credentials = r.getCredentials();
                remotedAccessKeyId = credentials.getAccessKeyId();
                remotedSecretAccessKey = credentials.getSecretAccessKey();
                remotedSessionToken = credentials.getSessionToken();
                LOGGER.log(Level.FINE, "GetFederationToken succeeded; using {0}", remotedAccessKeyId);
            }
            create(agentLogStreamName);
            return new Auth(remotedAccessKeyId, remotedSecretAccessKey, remotedSessionToken, region, agentLogStreamName);
        }

        /** @see <a href="https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/iam-access-control-overview-cwl.html">Reference</a> */
        private String policy(String agentLogStreamName) {
            return "{\"Version\": \"2012-10-17\", \"Statement\": [" +
                   "{\"Effect\": \"Allow\", \"Action\": [\"logs:PutLogEvents\"], \"Resource\": [\"arn:aws:logs:*:*:log-group:" + logGroupName + ":log-stream:" + agentLogStreamName + "\"]}" +
                   "]}";
        }

        @Override public void notifyShutdown(String agentLogStreamName) {
            synchronized (agentLogStreamNames) {
                agentLogStreamNames.remove(agentLogStreamName);
            }
        }


    }

    private static final class AgentState extends LogStreamState {

        private final @Nonnull MasterCalls masterCalls;
        private @CheckForNull AWSLogs client;
        private @Nullable String logStreamName;

        AgentState(String logGroupName, String logStreamNameBase, MasterCalls masterCalls) {
            super(logGroupName, logStreamNameBase);
            this.masterCalls = masterCalls;
            JenkinsJVM.checkNotJenkinsJVM();
        }

        @Override protected StateSupplier remote() {
            return new StateSupplier(logGroupName, logStreamNameBase, masterCalls);
        }

        @Override protected synchronized AWSLogs client() throws IOException {
            if (client == null) {
                Auth auth = masterCalls.authenticate();
                client = auth.client();
                logStreamName = auth.logStreamName;
            }
            return client;
        }

        @Override protected String logStreamName() throws IOException {
            client();
            return logStreamName;
        }

        @Override synchronized protected void ensureRunning() {
            if (client == null) {
                schedule();
            }
        }

        @Override protected synchronized void shutDown() {
            if (client != null) {
                client.shutdown();
                client = null;
                masterCalls.notifyShutdown(logStreamName);
                logStreamName = null;
            }
        }

    }

    protected abstract @Nonnull StateSupplier remote();

    protected abstract @Nonnull AWSLogs client() throws IOException;

    protected abstract @Nonnull String logStreamName() throws IOException;

    protected abstract void ensureRunning() throws IOException;

    protected abstract void shutDown();

    boolean offer(InputLogEvent event) throws IOException, InterruptedException {
        ensureRunning();
        return events.offer(event, 1, TimeUnit.MINUTES);
    }

    protected void schedule() {
        new Thread(this::process, "CloudWatch Logs delivery: " + logGroupName + "/" + logStreamNameBase).start(); // TODO share threads between loggers using poll methods, or use NIO methods
    }

    private void process() {
        String logStreamName;
        AWSLogs currentClient;
        try {
            logStreamName = logStreamName();
            currentClient = client();
        } catch (Exception x) {
            LOGGER.log(Level.WARNING, null, x);
            shutDown();
            return;
        }
        String sequenceToken = null;
        MAIN: while (true) {
            List<InputLogEvent> processing = new ArrayList<>();
            if (events.drainTo(processing) == 0) {
                LOGGER.log(Level.FINEST, "waiting for events from {0}", new Object[] {logStreamName});
                // TODO better to use an executor service rather than a dedicated thread
                try {
                    Thread.sleep(200); // https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/cloudwatch_limits_cwl.html 5 reqs/s/stream
                } catch (InterruptedException x) {
                    LOGGER.log(Level.WARNING, null, x);
                }
                // TODO check if this has been idle for (say) 60s and if so, shut down (break MAIN), to be restarted if and when someone publishes something
                continue;
            }
            // TODO as per https://docs.aws.amazon.com/AmazonCloudWatchLogs/latest/APIReference/API_PutLogEvents.html verify that total size <1Mb (no documented error class for excess size?)
            assert !processing.isEmpty();
            while (true) {
                try {
                    PutLogEventsResult result = currentClient.putLogEvents(new PutLogEventsRequest().
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
                    // Normally happens when first starting to send to a given stream from a given node; but if something goes haywire, might happen later too.
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
                    LOGGER.log(Level.WARNING, "giving up on this stream", x);
                    break MAIN;
                }
            }
            LOGGER.log(Level.FINER, "sent {0} events @{1} from {2}", new Object[] {processing.size(), processing.get(processing.size() - 1).getTimestamp(), logStreamName});
        }
        shutDown();
    }

    /**
     * Authentication to AWS.
     * Used from agent JVMs.
     */
    private static final class Auth implements Serializable {
        private static final long serialVersionUID = 1;
        final @Nullable String accessKeyId; // TODO check actual nullability for these
        final @Nullable String secretAccessKey;
        final @Nullable String sessionToken;
        // TODO also track expiration time, and automatically shut down the client so that a new call to master must be made
        final @Nullable String region;
        final @Nonnull String logStreamName;
        Auth(String accessKeyId, String secretAccessKey, String sessionToken, String region, String logStreamName) {
            this.accessKeyId = accessKeyId;
            this.secretAccessKey = secretAccessKey;
            this.sessionToken = sessionToken;
            this.region = region;
            this.logStreamName = logStreamName;
        }
        AWSLogs client() {
            AWSLogsClientBuilder builder;
            if (accessKeyId != null) {
                builder = AWSLogsClientBuilder.standard();
                if (region != null) {
                    builder = builder.withRegion(region);
                }
                builder.withCredentials(new AWSStaticCredentialsProvider(new BasicSessionCredentials(accessKeyId, secretAccessKey, sessionToken)));
            } else {
                try {
                    builder = CloudWatchAwsGlobalConfiguration.getAWSLogsClientBuilder(region, null);
                } catch (IOException x) {
                    throw new RuntimeException(x);
                }
            }
            return builder.build();
        }
    }

    /**
     * AWS calls which for security reasons may only happen on the master.
     * An instance may be exported over the channel to allow the agent to obtain current information.
     */
    private interface MasterCalls {

        @Nonnull Auth authenticate() throws IOException;

        void notifyShutdown(String agentLogStreamName);

    }

    static final class StateSupplier implements SerializableOnlyOverRemoting {

        private static final long serialVersionUID = 1;

        private final String logGroupName;
        private final String logStreamNameBase;
        private final MasterCalls masterCalls;

        StateSupplier(String logGroupName, String logStreamNameBase, MasterCalls masterCalls) {
            this.logGroupName = logGroupName;
            this.logStreamNameBase = logStreamNameBase;
            this.masterCalls = masterCalls;
        }

        LogStreamState create() {
            return onAgent(logGroupName, logStreamNameBase, masterCalls);
        }

    }

}
