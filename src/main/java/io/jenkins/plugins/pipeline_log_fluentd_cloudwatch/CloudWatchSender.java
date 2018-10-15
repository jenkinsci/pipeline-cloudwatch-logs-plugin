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

import com.amazonaws.services.logs.model.InputLogEvent;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import hudson.AbortException;
import hudson.ExtensionList;
import hudson.console.LineTransformationOutputStream;
import hudson.model.BuildListener;
import java.io.Closeable;
import java.io.IOException;
import java.io.PrintStream;
import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.annotation.CheckForNull;
import javax.annotation.Nonnull;
import jenkins.util.JenkinsJVM;
import net.sf.json.JSONObject;

/**
 * Sends Pipeline build log lines to CloudWatch Logs.
 */
abstract class CloudWatchSender implements BuildListener, Closeable {

    private static final Logger LOGGER = Logger.getLogger(CloudWatchSender.class.getName());

    private static final long serialVersionUID = 1;

    protected final @Nonnull String logGroupName;
    /** for example {@code jenkinsci/git-plugin/master} */
    protected final @Nonnull String logStreamNameBase;
    /** for example {@code 123} */
    protected final @Nonnull String buildId;
    /** for example {@code 7} */
    protected final @CheckForNull String nodeId;
    private transient @CheckForNull PrintStream logger;
    @SuppressFBWarnings(value = "IS2_INCONSISTENT_SYNC", justification = "Only need to synchronize initialization; thereafter it remains set.")
    private transient @CheckForNull TimestampTracker timestampTracker;
    protected transient @CheckForNull LogStreamState state;

    protected CloudWatchSender(@Nonnull String logGroupName, @Nonnull String logStreamNameBase, @Nonnull String buildId, @CheckForNull String nodeId, @CheckForNull TimestampTracker timestampTracker) {
        this.logGroupName = Objects.requireNonNull(logGroupName);
        this.logStreamNameBase = Objects.requireNonNull(logStreamNameBase);
        this.buildId = Objects.requireNonNull(buildId);
        this.nodeId = nodeId;
        this.timestampTracker = timestampTracker;
    }

    protected abstract LogStreamState loadState();

    static final class MasterSender extends CloudWatchSender {

        private transient List<LogStreamState.StateSupplier> stateSuppliers;

        MasterSender(String logStreamNameBase, String buildId, String nodeId, TimestampTracker timestampTracker) throws IOException {
            super(logGroupName(), logStreamNameBase, buildId, nodeId, timestampTracker);
        }

        private static String logGroupName() throws IOException {
            String logGroupName = ExtensionList.lookupSingleton(CloudWatchAwsGlobalConfiguration.class).getLogGroupName();
            if (logGroupName == null) {
                throw new AbortException("You must specify the CloudWatch log group name");
            }
            return logGroupName;
        }

        @Override protected LogStreamState loadState() {
            return LogStreamState.onMaster(logGroupName, logStreamNameBase);
        }

        private Object writeReplace() throws IOException {
            if (state == null) {
                state = loadState();
            }
            LogStreamState.StateSupplier stateSupplier = state.remote();
            if (stateSuppliers == null) {
                stateSuppliers = new ArrayList<>();
            }
            stateSuppliers.add(stateSupplier); // need to hold this so that Remoting will not unexport it; TODO does not seem to work
            return new AgentSender(logGroupName, logStreamNameBase, buildId, nodeId, stateSupplier);
        }

    }

    static final class AgentSender extends CloudWatchSender {

        private final LogStreamState.StateSupplier stateSupplier;

        AgentSender(String logGroupName, String logStreamNameBase, String buildId, String nodeId, LogStreamState.StateSupplier stateSupplier) {
            super(logGroupName, logStreamNameBase, buildId, nodeId, /* do not currently bother to record events from agent side */null);
            this.stateSupplier = stateSupplier;
        }

        @Override protected LogStreamState loadState() {
            return stateSupplier.create();
        }

    }

    @Override
    public synchronized final PrintStream getLogger() {
        if (logger == null) {
            if (timestampTracker == null) {
                timestampTracker = new TimestampTracker(); // need to serialize messages though we are not coördinating with CloudWatchRetriever on the master side
            }
            state = loadState();
            try {
                logger = new PrintStream(new CloudWatchOutputStream(), true, "UTF-8");
            } catch (UnsupportedEncodingException x) {
                throw new AssertionError(x);
            }
        }
        return logger;
    }

    @Override
    public synchronized final void close() throws IOException {
        if (logger != null) {
            LOGGER.log(Level.FINE, "closing {0}/{1}#{2}", new Object[] {logStreamNameBase, buildId, nodeId});
            logger = null;
        }
        if (nodeId != null && JenkinsJVM.isJenkinsJVM()) {
            // Note that this does not necessarily shut down the AWSLogs client; that is shared across builds.
            PipelineBridge.get().close(logStreamNameBase, buildId);
        }
    }

    private class CloudWatchOutputStream extends LineTransformationOutputStream {
        
        @Override
        protected void eol(byte[] b, int len) throws IOException {
            synchronized (CloudWatchSender.this) {
                if (logger == null) {
                    LOGGER.log(Level.FINER, "refusing to schedule event from closed or broken {0}/{1}#{2}", new Object[] {logStreamNameBase, buildId, nodeId});
                    return;
                }
            }
            Map<String, Object> data = ConsoleNotes.parse(b, len);
            data.put("build", buildId);
            if (nodeId != null) {
                data.put("node", nodeId);
            }
            assert timestampTracker != null : "getLogger which creates CloudWatchOutputStream initializes it";
            long now = timestampTracker.eventSent(); // when the logger prints something, *not* when we send it to CWL
            data.put("timestamp", now); // TODO remove
            try {
                if (state.offer(new InputLogEvent().
                        withTimestamp(now).
                        withMessage(JSONObject.fromObject(data).toString()))) {
                    LOGGER.log(Level.FINER, "scheduled event @{0} from {1}/{2}#{3}", new Object[] {now, logStreamNameBase, buildId, nodeId});
                } else {
                    LOGGER.warning("Message buffer full, giving up");
                }
            } catch (Exception x) {
                LOGGER.log(Level.WARNING, "failed to send a message", x);
            }
        }

    }

}
