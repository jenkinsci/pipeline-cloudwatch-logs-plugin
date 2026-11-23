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
import com.cloudbees.jenkins.plugins.awscredentials.AmazonWebServicesCredentials;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import hudson.ExtensionList;
import hudson.Util;
import hudson.remoting.Channel;
import io.jenkins.plugins.aws.global_configuration.CredentialsAwsGlobalConfiguration;
import java.io.IOException;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.Comparator;
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
import edu.umd.cs.findbugs.annotations.CheckForNull;
import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;
import java.util.UUID;
import jenkins.agents.AgentToControllerCallable;
import jenkins.util.JenkinsJVM;
import software.amazon.awssdk.auth.credentials.AwsSessionCredentials;
import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.core.exception.SdkException;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.cloudwatchlogs.CloudWatchLogsClient;
import software.amazon.awssdk.services.cloudwatchlogs.CloudWatchLogsClientBuilder;
import software.amazon.awssdk.services.cloudwatchlogs.model.InputLogEvent;
import software.amazon.awssdk.services.cloudwatchlogs.model.InvalidParameterException;
import software.amazon.awssdk.services.cloudwatchlogs.model.InvalidSequenceTokenException;
import software.amazon.awssdk.services.sts.StsClient;
import software.amazon.awssdk.services.sts.StsClientBuilder;
import software.amazon.awssdk.services.sts.model.Credentials;

/**
 * What is happening in a given log stream.
 * This will be specific to a job and a node JVM, but not to a build.
 */
abstract class LogStreamState {

    private static final Logger LOGGER = Logger.getLogger(LogStreamState.class.getName());

    private final @NonNull BlockingQueue<InputLogEvent> events = new ArrayBlockingQueue<>(10_000); // https://docs.aws.amazon.com/AmazonCloudWatchLogs/latest/APIReference/API_PutLogEvents.html max batch size
    private long lastOffered;

    protected abstract LogGroupAndStream lgs();

    static final class MasterState extends LogStreamState {

        private static final Map<LogGroupAndStream, MasterState> masterStates = new ConcurrentHashMap<>();

        static MasterState of(LogGroupAndStream lgs) {
            return masterStates.computeIfAbsent(lgs, k -> new MasterState(k));
        }

        private final LogGroupAndStream lgs;
        private @CheckForNull CloudWatchLogsClient client;
        private final Set<String> agentLogStreamNames = new HashSet<>();

        private MasterState(LogGroupAndStream lgs) {
            this.lgs = lgs;
            JenkinsJVM.checkJenkinsJVM();
        }

        @Override
        protected LogGroupAndStream lgs() {
            return lgs;
        }

        @Override protected synchronized CloudWatchLogsClient client() throws IOException {
            if (client == null) {
                client = ExtensionList.lookupSingleton(CloudWatchAwsGlobalConfiguration.class).getCloudWatchLogsClient();
            }
            return client;
        }

        @Override protected String logStreamName() {
            return lgs.logStreamNameBase() + "@master";
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
                client.close();
                client = null;
            }
        }

        private void create(String logStreamName) throws IOException {
            var currentClient = client();
            boolean found = false;
            String token = null;
            do {
                var _token = token;
                var r = currentClient.describeLogStreams(b -> b.logGroupName(lgs.logGroupName()).logStreamNamePrefix(logStreamName).nextToken(_token));
                for (var ls : r.logStreams()) {
                    if (ls.logStreamName().equals(logStreamName)) {
                        found = true;
                    }
                }
                token = r.nextToken();
            } while (!found && token != null);
            if (!found) {
                // First-time project.
                LOGGER.log(Level.FINE, "Creating {0}", logStreamName);
                currentClient.createLogStream(b -> b.logGroupName(lgs.logGroupName()).logStreamName(logStreamName));
            }
        }

        Auth authenticate() throws IOException {
            CredentialsAwsGlobalConfiguration credentialsConfig = CredentialsAwsGlobalConfiguration.get();
            String region = credentialsConfig.getRegion();
            AmazonWebServicesCredentials jenkinsCredentials = credentialsConfig.getCredentials();
            var masterCredentials = jenkinsCredentials != null ? jenkinsCredentials.resolveCredentials() : DefaultCredentialsProvider.create().resolveCredentials();
            String agentLogStreamName;
            synchronized (agentLogStreamNames) {
                for (int i = 1; ; i++) {
                    String candidate = lgs.logStreamNameBase() + "@agent" + i;
                    if (agentLogStreamNames.add(candidate)) {
                        agentLogStreamName = candidate;
                        break;
                    }
                }
            }
            if (masterCredentials instanceof AwsSessionCredentials sessionCredentials) {
                // otherwise would just throw AWSSecurityTokenServiceException: Cannot call GetFederationToken with session credentials
                String role = System.getenv("AWS_CHAINED_ROLE"); // TODO define in CloudWatchAwsGlobalConfiguration?
                if (jenkinsCredentials instanceof AWSCredentialsImpl) {
                    role = Util.fixEmpty(((AWSCredentialsImpl) jenkinsCredentials).getIamRoleArn());
                }
                if (role != null) {
                    return assumeRole(role, region, agentLogStreamName);
                } else {
                    return new Auth(sessionCredentials, region, agentLogStreamName);
                }
            } else if (masterCredentials == null) {
                return new Auth(region, agentLogStreamName);
            } else {
                var builder = StsClient.builder();
                if (region != null) {
                    builder = builder.region(Region.of(region));
                }
                if (jenkinsCredentials != null) {
                    builder.credentialsProvider(jenkinsCredentials);
                }
                return getFederationToken(builder, region, agentLogStreamName);
            }
        }

        /**
         * Creates restricted session credentials for an agent using {@code AssumeRole}.
         */
        private Auth assumeRole(String role, String region, String agentLogStreamName) {
            // TODO would be cleaner if AmazonWebServicesCredentials had a getCredentials overload taking a policy
            var builder = StsClient.builder();
            if (region != null) {
                builder = builder.region(Region.of(region));
            }
            Credentials credentials = builder.build().assumeRole(b -> b.
                    roleArn(role).
                    roleSessionName("CloudWatchSender-" + UUID.randomUUID()).
                    policy(policy(agentLogStreamName))).
                credentials();
            Auth auth = new Auth(credentials, region, agentLogStreamName);
            LOGGER.fine(() -> "AssumeRole succeeded; using " + StsClient.builder().credentialsProvider(StaticCredentialsProvider.create(AwsSessionCredentials.create(credentials.accessKeyId(), credentials.secretAccessKey(), credentials.sessionToken()))).build().getCallerIdentity());
            return auth;
        }

        /**
         * Creates restricted session credentials for an agent using {@code GetFederationToken}.
         */
        private Auth getFederationToken(StsClientBuilder builder, String region, String agentLogStreamName) {
            Auth auth = new Auth(builder.build().getFederationToken(b -> b.
                    name("CloudWatchSender-" + UUID.randomUUID()).
                    policy(policy(agentLogStreamName))).
                credentials(), region, agentLogStreamName);
            LOGGER.log(Level.FINE, "GetFederationToken succeeded; using {0}", auth.accessKeyId);
            return auth;
        }

        /** @see <a href="https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/iam-access-control-overview-cwl.html">Reference</a> */
        private String policy(String agentLogStreamName) {
            return "{\"Version\": \"2012-10-17\", \"Statement\": [" +
                   "{\"Effect\": \"Allow\", \"Action\": [\"logs:PutLogEvents\", \"logs:GetLogEvents\"], " +
                    "\"Resource\": [\"arn:aws:logs:*:*:log-group:" + lgs.logGroupName() + ":log-stream:" + agentLogStreamName + "\"]}" +
                   "]}";
        }

        void notifyShutdown(String agentLogStreamName) {
            synchronized (agentLogStreamNames) {
                agentLogStreamNames.remove(agentLogStreamName);
            }
        }

    }
    
    static @CheckForNull String validate(@NonNull String logGroupName) throws IOException {
        Auth auth = MasterState.of(new LogGroupAndStream(logGroupName, "__example__")).authenticate();
        if (auth.restricted) {
            return null;
        } else if (auth.accessKeyId != null) {
            return "Giving up on limiting session credentials to a policy; using " + auth.accessKeyId + " as is: " +
                StsClient.create().getCallerIdentity();
        } else {
            return "No AWS credentials to be found, giving up on limiting to a policy";
        }
    }

    private record Authenticate(AgentToControllerCallable.TrustedObject<LogGroupAndStream> lgs) implements AgentToControllerCallable<Auth, IOException> {

        @Override public Auth call() throws IOException {
            var state = MasterState.of(lgs.o());
            Auth auth = state.authenticate();
            state.create(auth.logStreamName.o());
            return auth;
        }

    }

    private record NotifyShutdown(AgentToControllerCallable.TrustedObject<LogGroupAndStream> lgs, AgentToControllerCallable.TrustedObject<String> agentLogStreamName) implements AgentToControllerCallable<Void, RuntimeException> {

        @Override public Void call() {
            var state = MasterState.of(lgs.o());
            state.notifyShutdown(agentLogStreamName.o());
            return null;
        }

    }

    static final class AgentState extends LogStreamState {

        private static final Map<LogGroupAndStream, AgentState> agentStates = new ConcurrentHashMap<>();

        static AgentState of(AgentToControllerCallable.TrustedObject<LogGroupAndStream> lgs, Channel channel) {
            return agentStates.computeIfAbsent(lgs.o(), k -> new AgentState(lgs, channel));
        }

        private final @NonNull AgentToControllerCallable.TrustedObject<LogGroupAndStream> lgs;
        private @CheckForNull CloudWatchLogsClient client;
        private @Nullable AgentToControllerCallable.TrustedObject<String> logStreamName;
        private final @NonNull Channel channel;

        AgentState(AgentToControllerCallable.TrustedObject<LogGroupAndStream> lgs, Channel channel) {
            this.lgs = lgs;
            this.channel = channel;
            JenkinsJVM.checkNotJenkinsJVM();
        }

        @Override protected LogGroupAndStream lgs() {
            return lgs.o();
        }

        @Override protected synchronized CloudWatchLogsClient client() throws IOException, InterruptedException {
            if (client == null) {
                Auth auth = channel.call(new Authenticate(lgs));
                client = auth.client();
                logStreamName = auth.logStreamName;
            }
            return client;
        }

        @Override protected String logStreamName() throws IOException, InterruptedException {
            client();
            return logStreamName.o();
        }

        @Override synchronized protected void ensureRunning() {
            if (client == null) {
                schedule();
            }
        }

        @Override protected synchronized void shutDown() {
            if (client != null) {
                client.close();
                client = null;
                try {
                    channel.callAsync(new NotifyShutdown(lgs, logStreamName));
                } catch (Exception x) {
                    LOGGER.log(Level.WARNING, null, x);
                }
                logStreamName = null;
            }
        }

    }

    protected abstract @NonNull CloudWatchLogsClient client() throws IOException, InterruptedException;

    protected abstract @NonNull String logStreamName() throws IOException, InterruptedException;

    protected abstract void ensureRunning() throws IOException;

    protected abstract void shutDown();

    boolean offer(InputLogEvent event) throws IOException, InterruptedException {
        ensureRunning();
        lastOffered = Math.max(lastOffered, event.timestamp());
        return events.offer(event, 1, TimeUnit.MINUTES);
    }

    protected void schedule() {
        new Thread(this::process, "CloudWatch Logs delivery: " + lgs().logGroupName() + "/" + lgs().logStreamNameBase()).start(); // TODO share threads between loggers using poll methods, or use NIO methods
    }

    private void process() {
        String logStreamName;
        CloudWatchLogsClient currentClient;
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
            processing.sort(Comparator.comparing(InputLogEvent::timestamp));
            while (true) {
                try {
                    var _sequenceToken = sequenceToken;
                    var result = currentClient.putLogEvents(b -> b.
                            logGroupName(lgs().logGroupName()).
                            logStreamName(logStreamName).
                            sequenceToken(_sequenceToken).
                            logEvents(processing));
                    sequenceToken = result.nextSequenceToken();
                    var problems = result.rejectedLogEventsInfo();
                    if (problems != null) {
                        LOGGER.log(Level.WARNING, "Rejected some log events: {0}", problems);
                    }
                    break;
                } catch (InvalidSequenceTokenException x) {
                    // Normally happens when first starting to send to a given stream from a given node; but if something goes haywire, might happen later too.
                    LOGGER.fine("Recovering from InvalidSequenceTokenException");
                    sequenceToken = x.expectedSequenceToken();
                    // and retry
                } catch (InvalidParameterException x) {
                    LOGGER.log(Level.WARNING, null, x);
                    break MAIN;
                } catch (SdkException x) {
                    // E.g.: CloudWatchLogsException: Rate exceeded (Service: AWSLogs; Status Code: 400; Error Code: ThrottlingException; Request ID: …)
                    LOGGER.log(Level.FINE, "retrying", x);
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
            LOGGER.log(Level.FINER, "sent {0} events @{1} from {2}", new Object[] {processing.size(), processing.get(processing.size() - 1).timestamp(), logStreamName});
        }
        shutDown();
    }

    void flush() throws IOException {
        LOGGER.log(Level.FINE, "flushing {0}", lgs().logStreamNameBase());
        long start = System.nanoTime();
        while (System.nanoTime() - start < TimeUnit.MINUTES.toNanos(1)) {
            try {
                if (events.isEmpty()) {
                    if (lastOffered > 0) {
                        LOGGER.log(Level.FINER, "all events up to {0} delivered in {1}; confirming receipt", new Object[] {lastOffered, lgs().logStreamNameBase()});
                        String logStreamName = logStreamName();
                        if (client().getLogEvents(b -> b.logGroupName(lgs().logGroupName()).logStreamName(logStreamName).limit(1).startTime(lastOffered)).events().isEmpty()) {
                            LOGGER.log(Level.FINER, "delivered an event in {0} with timestamp={1} but it has not yet been received", new Object[] {logStreamName, lastOffered});
                        } else {
                            LOGGER.log(Level.FINER, "confirmed event delivery in {0} with timestamp={1}", new Object[] {logStreamName, lastOffered});
                            return;
                        }
                    } else {
                        LOGGER.log(Level.FINER, "no events delivered in {0}", lgs().logStreamNameBase());
                        return;
                    }
                }
                Thread.sleep(100);
            } catch (IOException x) {
                LOGGER.log(Level.FINER, null, x);
                throw x;
            } catch (Exception x) {
                LOGGER.log(Level.FINER, null, x);
                throw new IOException(x);
            }
        }
        throw new IOException("there are still unflushed log events");
    }

    /**
     * Authentication to AWS.
     * Used from agent JVMs.
     */
    private static final class Auth implements Serializable { // TODO use record
        private static final long serialVersionUID = 1;
        final @CheckForNull String accessKeyId;
        final @Nullable String secretAccessKey;
        final @Nullable String sessionToken;
        // TODO also track expiration time, and automatically shut down the client so that a new call to master must be made
        final @CheckForNull String region;
        final @NonNull AgentToControllerCallable.TrustedObject<String> logStreamName;
        /** Whether {@link MasterState#policy} was applied. */
        @SuppressFBWarnings(value = "SE_TRANSIENT_FIELD_NOT_RESTORED", justification = "only used in validation")
        transient final boolean restricted;
        Auth(Credentials credentials, String region, String logStreamName) {
            this(credentials.accessKeyId(), credentials.secretAccessKey(), credentials.sessionToken(), region, logStreamName, true);
        }
        Auth(AwsSessionCredentials credentials, String region, String logStreamName) {
            this(credentials.accessKeyId(), credentials.secretAccessKey(), credentials.sessionToken(), region, logStreamName, false);
        }
        Auth(String region, String logStreamName) {
            this(null, null, null, region, logStreamName, false);
        }
        private Auth(String accessKeyId, String secretAccessKey, String sessionToken, String region, String logStreamName, boolean restricted) {
            this.accessKeyId = accessKeyId;
            this.secretAccessKey = secretAccessKey;
            this.sessionToken = sessionToken;
            this.region = region;
            this.logStreamName = new AgentToControllerCallable.TrustedObject<>(logStreamName);
            this.restricted = restricted;
        }
        CloudWatchLogsClient client() {
            CloudWatchLogsClientBuilder builder;
            if (accessKeyId != null) {
                builder = CloudWatchLogsClient.builder();
                if (region != null) {
                    builder = builder.region(Region.of(region));
                }
                builder.credentialsProvider(StaticCredentialsProvider.create(AwsSessionCredentials.create(accessKeyId, secretAccessKey, sessionToken)));
                return builder.build();
            } else {
                return CloudWatchAwsGlobalConfiguration.getCloudWatchLogsClient(region, null);
            }
        }
    }

}
