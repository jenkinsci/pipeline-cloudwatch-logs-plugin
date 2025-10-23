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

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class TimestampTrackerTest {

    @Test
    void monoticallyIncrease() {
        assertEquals(1234, TimestampTracker.monoticallyIncrease(0, 1234));
        assertEquals(1235, TimestampTracker.monoticallyIncrease(1234, 1234));
        assertEquals(1236, TimestampTracker.monoticallyIncrease(1235, 1234));
        assertEquals(3000, TimestampTracker.monoticallyIncrease(3000, 1234));
    }

    @Test
    void checkCompletion() {
        TimestampTracker tracker = new TimestampTracker();
        assertTrue(tracker.checkCompletion(timestamp -> true));
        assertTrue(tracker.checkCompletion(timestamp -> false));

        tracker.eventSent();
        assertTrue(tracker.checkCompletion(timestamp -> true));

        tracker.eventSent();
        assertFalse(tracker.checkCompletion(timestamp -> false));

        tracker.eventSent();
        assertTrue(tracker.checkCompletion(timestamp -> {
            tracker.eventSent();
            return true;
        }));

        tracker.eventSent();
        assertFalse(tracker.checkCompletion(timestamp -> {
            tracker.eventSent();
            return false;
        }));
    }
}
