package io.jenkins.plugins.pipeline_cloudwatch_logs;

import java.io.Serializable;

record LogGroupAndStream(String logGroupName, String logStreamNameBase) implements Serializable {}
