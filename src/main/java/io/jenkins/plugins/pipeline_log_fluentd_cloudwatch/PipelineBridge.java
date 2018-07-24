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

import hudson.Extension;
import hudson.console.AnnotatedLargeText;
import hudson.model.BuildListener;
import hudson.model.Queue;
import hudson.model.Run;
import hudson.model.TaskListener;
import java.io.IOException;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.jenkinsci.plugins.workflow.flow.FlowExecutionOwner;
import org.jenkinsci.plugins.workflow.graph.FlowNode;
import org.jenkinsci.plugins.workflow.log.BrokenLogStorage;
import org.jenkinsci.plugins.workflow.log.LogStorage;
import org.jenkinsci.plugins.workflow.log.LogStorageFactory;

/**
 * Binds fluentd and CloudWatch to Pipeline logs.
 */
@Extension
public final class PipelineBridge implements LogStorageFactory {

    private final Map<String, TimestampTracker> timestampTrackers = new ConcurrentHashMap<>();

    @Override
    public LogStorage forBuild(FlowExecutionOwner owner) {
        final String logStreamName;
        final String buildId;
        try {
            Queue.Executable exec = owner.getExecutable();
            if (exec instanceof Run) {
                Run<?, ?> b = (Run<?, ?>) exec;
                logStreamName = b.getParent().getFullName();
                buildId = b.getId();
            } else {
                return null;
            }
        } catch (IOException x) {
            return new BrokenLogStorage(x);
        }
        return new LogStorage() {
            @Override
            public BuildListener overallListener() throws IOException, InterruptedException {
                return new FluentdLogger(logStreamName, buildId, null, timestampTracker());
            }
            @Override
            public TaskListener nodeListener(FlowNode node) throws IOException, InterruptedException {
                return new FluentdLogger(logStreamName, buildId, node.getId(), timestampTracker());
            }
            @Override
            public AnnotatedLargeText<FlowExecutionOwner.Executable> overallLog(FlowExecutionOwner.Executable build, boolean complete) {
                try {
                    return new CloudWatchRetriever(logStreamName, buildId, timestampTracker()).overallLog(build, complete);
                } catch (Exception x) {
                    return new BrokenLogStorage(x).overallLog(build, complete);
                }
            }
            @Override
            public AnnotatedLargeText<FlowNode> stepLog(FlowNode node, boolean complete) {
                try {
                    return new CloudWatchRetriever(logStreamName, buildId, timestampTracker()).stepLog(node, complete);
                } catch (Exception x) {
                    return new BrokenLogStorage(x).stepLog(node, complete);
                }
            }
            private TimestampTracker timestampTracker() {
                return timestampTrackers.computeIfAbsent(logStreamName + "#" + buildId, k -> new TimestampTracker());
            }
        };
    }

}
