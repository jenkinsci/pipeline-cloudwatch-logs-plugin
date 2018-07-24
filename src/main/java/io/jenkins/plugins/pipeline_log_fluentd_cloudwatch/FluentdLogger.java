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

import hudson.console.LineTransformationOutputStream;
import hudson.model.BuildListener;
import hudson.remoting.Channel;
import java.io.IOException;
import java.io.PrintStream;
import java.io.UnsupportedEncodingException;
import java.util.Map;
import javax.annotation.CheckForNull;
import org.komamitsu.fluency.EventTime;
import org.komamitsu.fluency.Fluency;

/**
 * Sends Pipeline build log lines to fluentd.
 */
final class FluentdLogger implements BuildListener {

    private static final long serialVersionUID = 1;

    private final String logStreamName;
    private final String buildId;
    private final @CheckForNull String nodeId;
    private final String host;
    private final int port;
    private transient PrintStream logger;
    private final String sender;
    private transient @CheckForNull TimestampTracker timestampTracker;

    FluentdLogger(String logStreamName, String buildId, @CheckForNull String nodeId, TimestampTracker timestampTracker) {
        this(logStreamName, buildId, nodeId, host(), port(), "master", timestampTracker);
    }

    private static String host() {
        String host = System.getenv("FLUENTD_SERVICE_HOST");
        return host != null ? host : "localhost";
    }

    private static int port() {
        String port = System.getenv("FLUENTD_SERVICE_PORT_TCP");
        return port == null ? 24224 : Integer.parseInt(port);
    }

    private FluentdLogger(String logStreamName, String buildId, @CheckForNull String nodeId, String host, int port, String sender, TimestampTracker timestampTracker) {
        this.logStreamName = logStreamName;
        this.buildId = buildId;
        this.nodeId = nodeId;
        this.host = host;
        this.port = port;
        this.sender = sender;
        this.timestampTracker = timestampTracker;
    }

    private Object writeReplace() {
        return new FluentdLogger(logStreamName, buildId, nodeId, host, port, Channel.current().getName(), /* do not currently bother to record events from agent side */null);
    }

    @Override
    public PrintStream getLogger() {
        if (logger == null) {
            try {
                logger = new PrintStream(new FluentdOutputStream(), true, "UTF-8");
            } catch (UnsupportedEncodingException x) {
                throw new AssertionError(x);
            }
        }
        return logger;
    }

    private class FluentdOutputStream extends LineTransformationOutputStream {
        
        private final Fluency logger;

        FluentdOutputStream() {
            try {
                logger = Fluency.defaultFluency(host, port);
            } catch (IOException x) { // https://github.com/komamitsu/fluency/pull/99
                throw new RuntimeException(x);
            }
        }

        @Override
        protected void eol(byte[] b, int len) throws IOException {
            Map<String, Object> data = ConsoleNotes.parse(b, len);
            data.put("build", buildId);
            if (nodeId != null) {
                data.put("node", nodeId);
            }
            data.put("sender", sender); // for diagnostic purposes; could be dropped to avoid overhead
            long now = System.currentTimeMillis();
            data.put("timestamp", now); // TODO pending https://github.com/fluent-plugins-nursery/fluent-plugin-cloudwatch-logs/pull/108
            logger.emit(logStreamName, EventTime.fromEpochMilli(now), data);
            if (timestampTracker != null) {
                timestampTracker.eventSent(now);
            }
        }

        @Override
        public void flush() throws IOException {
            super.flush();
            logger.flush();
        }

        @Override
        public void close() throws IOException {
            super.close();
            logger.close();
        }

    }

}
