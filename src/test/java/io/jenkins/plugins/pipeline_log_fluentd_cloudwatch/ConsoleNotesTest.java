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

import hudson.console.ConsoleNote;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import net.sf.json.JSONObject;
import static org.hamcrest.Matchers.*;
import static org.junit.Assert.*;
import org.junit.Test;

public class ConsoleNotesTest {

    @Test
    public void parse() throws Exception {
        assertParse("some message\n");
        assertParse("some message\r\n");
        assertParse("\u001b[8mha:////SomeJunk+AAAA\u001b[0m[Pipeline] }\n");
        assertParse("Running on \u001b[8mha:////SomeJunkAAAA==\u001b[0mremote in /workspace/p\n");
        assertParse("Something at the end\u001b[8mha:////SomeJunkAAAA==\u001b[0m\n");
        assertParse("\u001b[8mha:////FirstJunkAAAA==\u001b[0m and then \u001b[8mha:////SecondJunk+AAAA\u001b[0m\n");
        assertParse("first got \u001b[8mha:////FirstJunkAAAA==\u001b[0m and then \u001b[8mha:////SecondJunk+AAAA\u001b[0m at the end\n");
        assertParse("got \u001b[8mha:////FirstJunkAAAA==\u001b[0m\u001b[8mha:////SecondJunk+AAAA\u001b[0m back to back\n");
        assertParse("this \u001b[8mha:////SomeJunkAAAA== is broken\n");
        assertParse("no final newline");
    }

    private static void assertParse(String line) throws Exception {
        byte[] data = line.getBytes(StandardCharsets.UTF_8);
        Map<String, Object> map = ConsoleNotes.parse(data, data.length);
        JSONObject json = JSONObject.fromObject(map);
        StringWriter w = new StringWriter();
        ConsoleNotes.write(w, json);
        System.err.println(json);
        System.err.print(w);
        if (line.contains(ConsoleNote.PREAMBLE_STR) && line.contains(ConsoleNote.POSTAMBLE_STR)) {
            assertThat(line + " converted to " + json, (String) map.get("message"), not(containsString("\u001b")));
        }
        assertEquals(line + " converted to " + json, line.replaceFirst("[\r\n]+$", "") + "\n", w.toString());
    }

}
