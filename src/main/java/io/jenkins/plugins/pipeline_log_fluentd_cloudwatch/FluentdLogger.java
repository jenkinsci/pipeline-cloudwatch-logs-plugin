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

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import hudson.console.LineTransformationOutputStream;
import hudson.model.BuildListener;
import hudson.remoting.Channel;
import java.io.Closeable;
import java.io.IOException;
import java.io.PrintStream;
import java.io.UnsupportedEncodingException;
import java.util.Map;

import javax.annotation.CheckForNull;

import java.util.Objects;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.annotation.CheckForNull;
import javax.annotation.Nonnull;
import org.komamitsu.fluency.EventTime;
import org.komamitsu.fluency.Fluency;

import hudson.ExtensionList;
import hudson.console.LineTransformationOutputStream;
import hudson.model.BuildListener;
import hudson.remoting.Channel;

/**
 * Sends Pipeline build log lines to fluentd.
 */
final class FluentdLogger implements BuildListener, Closeable {

    static {
        // TODO pending https://github.com/komamitsu/fluency/pull/100
        Logger.getLogger("org.komamitsu.fluency.buffer.Buffer").setLevel(Level.WARNING);
    }

    private static final Logger LOGGER = Logger.getLogger(FluentdLogger.class.getName());

    private static final long serialVersionUID = 1;

    private final @Nonnull String logStreamName;
    private final @Nonnull String buildId;
    private final @CheckForNull String nodeId;
    private final @Nonnull String host;
    private final int port;
    private transient @CheckForNull PrintStream logger;
    private final @Nonnull String sender;
    @SuppressFBWarnings(value = "IS2_INCONSISTENT_SYNC", justification = "Only need to synchronize initialization; thereafter it remains set.")
    private transient @CheckForNull TimestampTracker timestampTracker;

    FluentdLogger(@Nonnull String logStreamName, @Nonnull String buildId, @CheckForNull String nodeId, @CheckForNull TimestampTracker timestampTracker) {
        this(logStreamName, buildId, nodeId, host(), port(), "master", timestampTracker);
    }

    private static String host() {
        CloudWatchAwsGlobalConfiguration configuration = ExtensionList
                .lookupSingleton(CloudWatchAwsGlobalConfiguration.class);
        return configuration.computeFluentdHost();
    }

    private static int port() {
        CloudWatchAwsGlobalConfiguration configuration = ExtensionList
                .lookupSingleton(CloudWatchAwsGlobalConfiguration.class);
        return configuration.computeFluentdPort();
    }

    private FluentdLogger(@Nonnull String logStreamName, @Nonnull String buildId, @CheckForNull String nodeId, @Nonnull String host, int port, @Nonnull String sender, @CheckForNull TimestampTracker timestampTracker) {
        this.logStreamName = Objects.requireNonNull(logStreamName);
        this.buildId = Objects.requireNonNull(buildId);
        this.nodeId = nodeId;
        this.host = Objects.requireNonNull(host);
        this.port = port;
        this.sender = sender;
        this.timestampTracker = timestampTracker;
    }

    private Object writeReplace() {
        return new FluentdLogger(logStreamName, buildId, nodeId, host, port, Channel.current().getName(), /* do not currently bother to record events from agent side */null);
    }

    @Override
    public synchronized PrintStream getLogger() {
        if (logger == null) {
            if (timestampTracker == null) {
                timestampTracker = new TimestampTracker(); // need to serialize messages though we are not coördinating with CloudWatchRetriever on the master side
            }
            try {
                logger = new PrintStream(new FluentdOutputStream(), true, "UTF-8");
            } catch (UnsupportedEncodingException x) {
                throw new AssertionError(x);
            }
        }
        return logger;
    }

    @Override
    public synchronized void close() throws IOException {
        if (logger != null) {
            logger.close();
            logger = null;
        }
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
            assert timestampTracker != null : "getLogger which creates FluentdOutputStream initializes it";
            long now = timestampTracker.eventSent();
            data.put("timestamp", now); // TODO pending https://github.com/fluent-plugins-nursery/fluent-plugin-cloudwatch-logs/pull/108
            logger.emit(logStreamName, EventTime.fromEpochMilli(now), data);
            LOGGER.log(Level.FINER, "sent event @{0} from {1}/{2}#{3}", new Object[] {now, logStreamName, buildId, nodeId});
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
