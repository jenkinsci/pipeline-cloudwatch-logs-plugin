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
import hudson.model.Action;
import hudson.model.Run;
import java.util.Collection;
import java.util.Collections;
import jenkins.model.TransientActionFactory;
import org.jenkinsci.plugins.workflow.flow.FlowExecutionOwner;

/**
 * Displays a link to CloudWatch Logs in the AWS Console.
 */
public final class CloudWatchWebLink implements Action {

    private final String logStreamName;
    private final String buildId;

    private CloudWatchWebLink(Run<?, ?> build) {
        this.logStreamName = build.getParent().getFullName();
        this.buildId = build.getId();
    }

    @Override
    public String getIconFileName() {
        return "/plugin/pipeline-log-fluentd-cloudwatch/images/24x24/cloudwatch.png";
    }

    @Override
    public String getDisplayName() {
        return "CloudWatch Logs";
    }

    @Override
    public String getUrlName() {
        // TODO determine what manner of URL encoding might be necessary for unusual job names
        return "https://console.aws.amazon.com/cloudwatch/home#logEventViewer:group=" + System.getenv("CLOUDWATCH_LOG_GROUP_NAME") + ";stream=" + logStreamName + ";filter=%257B%2524.build%2520%253D%2520%2522" + buildId + "%2522%257D";
    }

    @Extension
    public static final class Factory extends TransientActionFactory<FlowExecutionOwner.Executable> {

        @Override
        public Class<FlowExecutionOwner.Executable> type() {
            return FlowExecutionOwner.Executable.class;
        }

        @Override
        public Collection<? extends Action> createFor(FlowExecutionOwner.Executable target) {
            if (target instanceof Run) {
                Run<?, ?> build = (Run<?, ?>) target;
                return Collections.singleton(new CloudWatchWebLink(build));
            } else {
                return Collections.emptySet();
            }
        }

    }

}
