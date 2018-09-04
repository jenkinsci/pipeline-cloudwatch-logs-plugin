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

import static org.hamcrest.Matchers.*;
import static org.junit.Assert.*;
import static org.junit.Assume.*;

import java.net.ConnectException;
import java.util.Collections;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Level;

import org.jenkinsci.plugins.workflow.log.LogStorage;
import org.jenkinsci.plugins.workflow.log.LogStorageTestBase;
import org.junit.Before;
import org.junit.Rule;
import org.jvnet.hudson.test.LoggerRule;
import org.komamitsu.fluency.Fluency;
import org.komamitsu.fluency.flusher.SyncFlusher;
import org.komamitsu.fluency.sender.TCPSender;

import com.amazonaws.services.cloudwatch.model.ResourceNotFoundException;
import com.amazonaws.services.logs.AWSLogs;
import com.amazonaws.services.logs.model.FilterLogEventsRequest;
import com.amazonaws.services.logs.model.FilterLogEventsResult;

import hudson.ExtensionList;
import hudson.util.FormValidation;

public class PipelineBridgeTest extends LogStorageTestBase {

    private static final String LOG_STREAM_NAME = "PipelineBridgeTest";

    @Rule public LoggerRule logging = new LoggerRule().recordPackage(PipelineBridge.class, Level.FINER);
    private Map<String, TimestampTracker> timestampTrackers;
    private String id;

    @Before public void setUp() throws Exception {
        String logGroupName = System.getenv("CLOUDWATCH_LOG_GROUP_NAME");
        assumeThat("must define $CLOUDWATCH_LOG_GROUP_NAME", logGroupName, notNullValue());
        CloudWatchAwsGlobalConfiguration configuration = ExtensionList.lookupSingleton(CloudWatchAwsGlobalConfiguration.class);
        FormValidation logGroupNameValidation = configuration.validate(logGroupName, null, null);
        assumeThat(logGroupNameValidation.toString(), logGroupNameValidation.kind, is(FormValidation.Kind.OK));
        configuration.setLogGroupName(logGroupName);
        // TODO reuse form validation when #6 is merged:
        try (Fluency fluency = new Fluency.Builder(new TCPSender.Config().setHost(FluentdLogger.host()).setPort(FluentdLogger.port()).createInstance()).setFlusherConfig(new SyncFlusher.Config().setFlushIntervalMillis(1000)).build()) {
            fluency.emit(LOG_STREAM_NAME, Collections.singletonMap("ping", true));
            fluency.flush();
        } catch (ConnectException x) {
            assumeNoException("set $FLUENTD_SERVICE_HOST / $FLUENTD_SERVICE_PORT_TCP as needed", x);
        }
        AWSLogs client = configuration.getAWSLogsClientBuilder().build();
        try {
            FilterLogEventsResult events = client.filterLogEvents(
                    new FilterLogEventsRequest().withLogGroupName(logGroupName).withLogStreamNames(LOG_STREAM_NAME));
            assertThat("Event didn't reach CloudWatch", events.getEvents(), not(empty()));
        } catch (ResourceNotFoundException e) {
            fail("Event didn't reach CloudWatch: " + e.getMessage());
        }
        timestampTrackers = new ConcurrentHashMap<>();
        id = UUID.randomUUID().toString();
    }

    @Override protected LogStorage createStorage() throws Exception {
        return new PipelineBridge.LogStorageImpl(LOG_STREAM_NAME, id, timestampTrackers);
    }

}
