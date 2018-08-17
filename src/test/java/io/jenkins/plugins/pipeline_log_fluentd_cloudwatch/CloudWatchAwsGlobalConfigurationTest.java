/*
 * The MIT License
 *
 * Copyright (c) 2018, CloudBees, Inc.
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

import static org.junit.Assert.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.Spy;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PowerMockIgnore;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;

import com.amazonaws.auth.AWSCredentialsProvider;
import com.amazonaws.auth.AWSSessionCredentials;
import com.amazonaws.auth.AWSStaticCredentialsProvider;
import com.amazonaws.auth.DefaultAWSCredentialsProviderChain;
import com.amazonaws.services.logs.AWSLogsClientBuilder;

import hudson.util.FormValidation;
import io.jenkins.plugins.aws.global_configuration.CredentialsAwsGlobalConfiguration;
import jenkins.model.Jenkins;

@RunWith(PowerMockRunner.class)
@PrepareForTest({ CredentialsAwsGlobalConfiguration.class, Jenkins.class })
@PowerMockIgnore({ "javax.management.*", "org.apache.http.conn.ssl.*", "com.amazonaws.http.conn.ssl.*",
        "javax.net.ssl.*" })
public class CloudWatchAwsGlobalConfigurationTest {

    private static String CREDENTIALS_ID = "CloudWatchAwsGlobalConfigurationTest";
    private static String REGION = "us-east-1";

    @Mock
    private Jenkins jenkins;

    @Spy
    private CloudWatchAwsGlobalConfiguration config = new CloudWatchAwsGlobalConfigurationStub();

    @Mock
    private CredentialsAwsGlobalConfiguration credentialsConfig;

    @Mock
    private AWSSessionCredentials credentials;

    @Before
    public void before() throws Exception {
        PowerMockito.mockStatic(CredentialsAwsGlobalConfiguration.class);
        when(CredentialsAwsGlobalConfiguration.get()).thenReturn(credentialsConfig);
        PowerMockito.mockStatic(Jenkins.class);
        when(Jenkins.getInstance()).thenReturn(jenkins);

        when(credentialsConfig.sessionCredentials(any(), eq(REGION), eq(CREDENTIALS_ID))).thenReturn(credentials);
    }

    @Test
    public void testValidate() throws Exception {
        FormValidation validation = config.validate("logGroup", REGION, CREDENTIALS_ID);
        assertEquals(FormValidation.Kind.OK, validation.kind);
        verify(config).filter(any(), eq("logGroup"));
    }

    @Test
    public void testGetAWSLogsClientBuilderDefaultCredentials() throws Exception {
        AWSLogsClientBuilder builder = config.getAWSLogsClientBuilder(null, null);
        assertNull(builder.getRegion());
        assertTrue(builder.getCredentials() instanceof DefaultAWSCredentialsProviderChain);
    }

    @Test
    public void testGetAWSLogsClientBuilderWithCredentials() throws Exception {
        AWSLogsClientBuilder builder = config.getAWSLogsClientBuilder(REGION, CREDENTIALS_ID);
        assertEquals(REGION, builder.getRegion());
        AWSCredentialsProvider credentialsProvider = builder.getCredentials();
        assertTrue(credentialsProvider instanceof AWSStaticCredentialsProvider);
        assertSame(credentials, credentialsProvider.getCredentials());
    }

}
