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

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import hudson.Extension;
import hudson.ExtensionList;
import hudson.console.AnnotatedLargeText;
import hudson.model.BuildListener;
import hudson.model.Queue;
import hudson.model.Run;
import hudson.model.TaskListener;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.jenkinsci.plugins.workflow.flow.FlowExecutionOwner;
import org.jenkinsci.plugins.workflow.graph.FlowNode;
import org.jenkinsci.plugins.workflow.log.BrokenLogStorage;
import org.jenkinsci.plugins.workflow.log.LogStorage;
import org.jenkinsci.plugins.workflow.log.LogStorageFactory;

/**
 * Binds CloudWatch to Pipeline logs.
 */
@Extension
public final class PipelineBridge implements LogStorageFactory {

    static {
        // Make sure JENKINS-52165 is enabled, or performance will be awful for remote shell steps.
        System.setProperty("org.jenkinsci.plugins.workflow.steps.durable_task.DurableTaskStep.USE_WATCHING", "true");
    }

    private static final Logger LOGGER = Logger.getLogger(PipelineBridge.class.getName());

    private final Map<String, TimestampTracker> timestampTrackers = new ConcurrentHashMap<>();
    private final Map<String, LogStorageImpl> impls = new ConcurrentHashMap<>();

    @Override
    public LogStorage forBuild(FlowExecutionOwner owner) {
        final String logStreamNameBase;
        final String buildId;
        try {
            Queue.Executable exec = owner.getExecutable();
            if (exec instanceof Run) {
                Run<?, ?> b = (Run<?, ?>) exec;
                // TODO escape [:*@%] in job names using %XX URL encoding
                logStreamNameBase = b.getParent().getFullName();
                buildId = b.getId();
            } else {
                return null;
            }
        } catch (IOException x) {
            return new BrokenLogStorage(x);
        }
        return forIDs(logStreamNameBase, buildId);
    }

    static PipelineBridge get() {
        return ExtensionList.lookupSingleton(PipelineBridge.class);
    }

    LogStorage forIDs(String logStreamNameBase, String buildId) {
        return impls.computeIfAbsent(logStreamNameBase + "#" + buildId, k -> new LogStorageImpl(logStreamNameBase, buildId, timestampTrackers));
    }

    void close(String logStreamNameBase, String buildId) {
        impls.remove(logStreamNameBase + "#" + buildId);
    }
    
    private static class LogStorageImpl implements LogStorage {

        private final String logStreamNameBase;
        private final String buildId;
        private final Map<String, TimestampTracker> timestampTrackers;

        LogStorageImpl(String logStreamName, String buildId, Map<String, TimestampTracker> timestampTrackers) {
            this.logStreamNameBase = logStreamName;
            this.buildId = buildId;
            this.timestampTrackers = timestampTrackers;
        }

        @Override
        public BuildListener overallListener() throws IOException, InterruptedException {
            return new CloudWatchSender.MasterSender(logStreamNameBase, buildId, null, timestampTracker());
        }

        @Override
        public TaskListener nodeListener(FlowNode node) throws IOException, InterruptedException {
            return new CloudWatchSender.MasterSender(logStreamNameBase, buildId, node.getId(), timestampTracker());
        }

        @Override
        public AnnotatedLargeText<FlowExecutionOwner.Executable> overallLog(FlowExecutionOwner.Executable build, boolean complete) {
            try {
                return new CloudWatchRetriever(logStreamNameBase, buildId, timestampTracker()).overallLog(build, complete);
            } catch (Exception x) {
                return new BrokenLogStorage(x).overallLog(build, complete);
            }
        }

        @Override
        public AnnotatedLargeText<FlowNode> stepLog(FlowNode node, boolean complete) {
            try {
                return new CloudWatchRetriever(logStreamNameBase, buildId, timestampTracker()).stepLog(node, complete);
            } catch (Exception x) {
                return new BrokenLogStorage(x).stepLog(node, complete);
            }
        }

        @SuppressFBWarnings(value = "BC_UNCONFIRMED_CAST", justification = "forBuild only accepts Run")
        @Deprecated
        @Override
        public File getLogFile(FlowExecutionOwner.Executable build, boolean complete) {
            AnnotatedLargeText<FlowExecutionOwner.Executable> logText = overallLog(build, complete);
            // Not creating a temp file since it would be too expensive to have multiples:
            File f = new File(((Run) build).getRootDir(), "log");
            f.deleteOnExit();
            try (OutputStream os = new FileOutputStream(f)) {
                // Similar to Run#writeWholeLogTo but terminates even if !complete:
                long pos = 0;
                while (true) {
                    long pos2 = logText.writeRawLogTo(pos, os);
                    if (pos2 <= pos) {
                        break;
                    }
                    pos = pos2;
                }
            } catch (Exception x) {
                LOGGER.log(Level.WARNING, null, x);
            }
            return f;
        }

        private TimestampTracker timestampTracker() {
            return timestampTrackers.computeIfAbsent(logStreamNameBase + "#" + buildId, k -> new TimestampTracker());
        }

    }

}
