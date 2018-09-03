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
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.annotation.CheckForNull;

import org.jenkinsci.plugins.workflow.flow.FlowExecutionOwner;
import org.jenkinsci.plugins.workflow.graph.FlowNode;
import org.jenkinsci.plugins.workflow.log.ConsoleAnnotators;
import org.jenkinsci.plugins.workflow.log.LogStorage;
import org.kohsuke.stapler.framework.io.ByteBuffer;

import com.amazonaws.services.logs.AWSLogs;
import com.amazonaws.services.logs.model.FilterLogEventsRequest;
import com.amazonaws.services.logs.model.FilterLogEventsResult;
import com.amazonaws.services.logs.model.FilteredLogEvent;
import com.amazonaws.services.logs.model.ResourceNotFoundException;

import hudson.AbortException;
import hudson.ExtensionList;
import hudson.Main;
import hudson.console.AnnotatedLargeText;
import hudson.console.ConsoleAnnotationOutputStream;
import java.io.InputStream;
import java.util.concurrent.atomic.AtomicInteger;
import net.sf.json.JSONObject;

/**
 * Retrieves build logs from CloudWatch.
 */
class CloudWatchRetriever {

    private static final Logger LOGGER = Logger.getLogger(CloudWatchRetriever.class.getName());

    private final String logStreamName;
    private final String buildId;
    private final TimestampTracker timestampTracker;
    private final String logGroupName;
    private final AWSLogs client;

    CloudWatchRetriever(String logStreamName, String buildId, TimestampTracker timestampTracker) throws IOException {
        this.logStreamName = logStreamName;
        this.buildId = buildId;
        this.timestampTracker = timestampTracker;
        CloudWatchAwsGlobalConfiguration configuration = ExtensionList.lookupSingleton(CloudWatchAwsGlobalConfiguration.class);
        logGroupName = configuration.getLogGroupName();
        if (logGroupName == null) {
            throw new AbortException("You must specify the CloudWatch log group name");
        }
        // TODO refresh client when configuration changes
        client = configuration.getAWSLogsClientBuilder().build();
    }

    AnnotatedLargeText<FlowExecutionOwner.Executable> overallLog(FlowExecutionOwner.Executable build, boolean complete) throws IOException, InterruptedException {
        return new OverallLog(build, complete);
    }

    AnnotatedLargeText<FlowNode> stepLog(FlowNode node, boolean completed) throws IOException {
        ByteBuffer buf = new ByteBuffer();
        boolean markedCompleted = completed && couldBeComplete();
        stream(buf, node.getId(), null);
        return new AnnotatedLargeText<>(buf, StandardCharsets.UTF_8, markedCompleted, node);
    }

    private class OverallLog extends AnnotatedLargeText<FlowExecutionOwner.Executable> {

        private final FlowExecutionOwner.Executable context;
        private final List<String> idsByLine = new ArrayList<>();
        private final ByteBuffer buf;

        OverallLog(FlowExecutionOwner.Executable build, boolean completed) throws IOException {
            this(new ByteBuffer(), completed, build);
        }

        private OverallLog(ByteBuffer buf, boolean completed, FlowExecutionOwner.Executable context) throws IOException {
            super(buf, StandardCharsets.UTF_8, completed && couldBeComplete(), context);
            this.context = context;
            stream(buf, null, idsByLine);
            this.buf = buf;
        }

        @Override
        public long writeHtmlTo(long start, final Writer w) throws IOException {
            if (start == 0 && /* would mess up PipelineBridgeTest */ !Main.isUnitTest) {
                String url = "https://console.aws.amazon.com/cloudwatch/home#logEventViewer:group=" + logGroupName + ";stream=" + logStreamName + ";filter=%257B%2524.build%2520%253D%2520%2522" + buildId + "%2522%257D";
                w.write("[view in <a href=\"" + url + "\" target=\"_blank\">AWS Console</a> if authorized]\n");
                // Should not affect the return value at all: Blue Ocean does not use writeHtmlTo, and regular console is not counting bytes.
            }
            AtomicInteger line = new AtomicInteger();
            if (start > 0) {
                long remaining = start;
                try (InputStream is = buf.newInputStream()) {
                    while (remaining > 0) {
                        int c = is.read();
                        if (c == -1) {
                            LOGGER.log(Level.WARNING, "EOF while calculating line numbers from {0} with remaining {1}", new Object[] {start, remaining});
                            break;
                        }
                        if (c == '\n') {
                            line.incrementAndGet();
                        }
                        remaining--;
                    }
                }
            }
            ConsoleAnnotationOutputStream<FlowExecutionOwner.Executable> caw = new ConsoleAnnotationOutputStream<FlowExecutionOwner.Executable>(w, ConsoleAnnotators.createAnnotator(context), context, StandardCharsets.UTF_8) {
                private String currentId;
                @Override
                protected void eol(byte[] in, int sz) throws IOException {
                    String id = idsByLine.get(line.getAndIncrement());
                    if (id != null) {
                        if (!id.equals(currentId)) {
                            if (currentId != null) {
                                w.write(LogStorage.endStep());
                            }
                            w.write(LogStorage.startStep(id));
                        }
                    } else if (currentId != null) {
                        w.write(LogStorage.endStep());
                    }
                    super.eol(in, sz);
                    currentId = id;
                }
                @Override
                public void flush() throws IOException {
                    super.flush();
                    if (currentId != null) {
                        w.write(LogStorage.endStep());
                    }
                }
            };
            long r = writeRawLogTo(start, caw);
            ConsoleAnnotators.setAnnotator(caw.getConsoleAnnotator());
            return r;
        }

    }

    /**
     * Whether it looks like we have received all the log lines sent for the build.
     */
    private boolean couldBeComplete() {
        return timestampTracker.checkCompletion(timestamp -> {
            // Do not use withStartTime(timestamp) as the fluentd bridge currently truncates milliseconds (see below).
            List<FilteredLogEvent> events;
            try {
                events = client.filterLogEvents(createFilter().withFilterPattern("{$.timestamp = " + timestamp + "}").withLimit(1)).getEvents();
            } catch (ResourceNotFoundException e) {
                LOGGER.log(Level.FINE, "{0} or its stream {1} do not exist: {2}", new Object[] {logGroupName, logStreamName, e.getMessage()});
                return false;
            }
            if (events.isEmpty()) {
                LOGGER.log(Level.FINE, "{0} contains no event in {1} with timestamp={2}", new Object[] {logGroupName, logStreamName, timestamp});
                return false;
            } else {
                LOGGER.log(Level.FINER, "{0} does contain an event in {1} with timestamp={2}", new Object[] {logGroupName, logStreamName, timestamp});
                return true;
            }
        });
    }

    /**
     * Gather the log text for one node or the entire build.
     * @param os where to send output
     * @param nodeId if defined, limit output to that coming from this node
     * @param idsByLine if defined, add a node ID or null per line printed
     */
    private void stream(OutputStream os, @CheckForNull String nodeId, @CheckForNull List<String> idsByLine) throws IOException {
        try (Writer w = new OutputStreamWriter(os, StandardCharsets.UTF_8)) {
            String token = null;
                do {
                    FilterLogEventsResult result = client.filterLogEvents(createFilter().withFilterPattern("{$.build = \"" + buildId + (nodeId == null ? "" : "\" && $.node = \"" + nodeId) + "\"}").withNextToken(token));
                    token = result.getNextToken();
                    List<FilteredLogEvent> events = result.getEvents();
                    LOGGER.log(Level.FINER, "event count {0} from group={1} stream={2} buildId={3} nodeId={4}", new Object[] {events.size(), logGroupName, logStreamName, buildId, nodeId});
                    // TODO pending https://github.com/fluent-plugins-nursery/fluent-plugin-cloudwatch-logs/pull/108:
                    events.sort(Comparator.comparingLong(e -> JSONObject.fromObject(e.getMessage()).optLong("timestamp", e.getTimestamp())));
                    for (FilteredLogEvent event : events) {
                        // TODO perhaps translate event.timestamp to a TimestampNote
                        JSONObject json = JSONObject.fromObject(event.getMessage());
                        assert buildId.equals(json.optString("build"));
                        ConsoleNotes.write(w, json);
                        if (idsByLine != null) {
                            idsByLine.add(json.optString("node", null));
                        }
                    }
                } while (token != null);
            w.flush();
        } catch (RuntimeException x) { // AWS SDK exceptions of various sorts
            throw new IOException(x);
        }
    }

    private FilterLogEventsRequest createFilter() {
        return new FilterLogEventsRequest().
            withLogGroupName(logGroupName).
            withLogStreamNames(logStreamName);
    }

}
