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

import java.util.function.Function;
import java.util.logging.Logger;

/**
 * For a given build, tracks the last event timestamp known to have been sent to fluentd.
 * When serving the log for that build, if the last observed timestamp is older, we wait until CloudWatch catches up.
 * Once it does, we remove the entry since we no longer need to catch up further.
 * <p>Also ensures that we use monotonically increasing timestamps at least for messages originating on a given node; strictly increasing up to some reasonable throughput.
 * <p>We are not bothering to persist this state, as it is only useful for a few seconds anyway.
 */
final class TimestampTracker {

    private static final Logger LOGGER = Logger.getLogger(TimestampTracker.class.getName());

    private long lastRecordedTimestamp;

    TimestampTracker() {
        LOGGER.fine("created new timestamp tracker");
    }

    /**
     * Called when we are delivering an event to fluentd.
     */
    synchronized long eventSent() {
        return lastRecordedTimestamp = monoticallyIncrease(lastRecordedTimestamp, System.currentTimeMillis());
    }

    /** Preferably {@code now}; {@code lastRecordedTimestamp + 1} if necessary to increase strictly; except if that would be >1s in the future, in which case nonstrictly. */
    static long monoticallyIncrease(long lastRecordedTimestamp, long now) {
        if (now > lastRecordedTimestamp) {
            return now;
        } else if (lastRecordedTimestamp > now + 1000) {
            return lastRecordedTimestamp;
        } else {
            return lastRecordedTimestamp + 1;
        }
    }

    /**
     * Called when we are displaying events from CloudWatch.
     * @param check takes the last recorded timestamp and indicates whether that is now visible
     * @return true if it is visible
     */
    boolean checkCompletion(Function<Long, Boolean> check) {
        long timestamp;
        synchronized (this) {
            timestamp = lastRecordedTimestamp;
        }
        if (timestamp == 0) {
            return true; // maybe?
        }
        if (check.apply(timestamp)) {
            synchronized (this) {
                if (lastRecordedTimestamp == timestamp) {
                    lastRecordedTimestamp = 0;
                }
            }
            return true;
        } else {
            return false;
        }
    }

}
