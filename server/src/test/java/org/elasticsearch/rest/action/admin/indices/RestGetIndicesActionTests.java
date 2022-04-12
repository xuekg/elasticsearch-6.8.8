/*
 * Licensed to Elasticsearch under one or more contributor
 * license agreements. See the NOTICE file distributed with
 * this work for additional information regarding copyright
 * ownership. Elasticsearch licenses this file to you under
 * the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.elasticsearch.rest.action.admin.indices;

import org.elasticsearch.client.node.NodeClient;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.rest.RestController;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.test.ESTestCase;
import org.elasticsearch.test.rest.FakeRestRequest;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import static org.elasticsearch.rest.BaseRestHandler.INCLUDE_TYPE_NAME_PARAMETER;
import static org.mockito.Mockito.mock;

public class RestGetIndicesActionTests extends ESTestCase {

    /**
     * Test that ommiting setting the "include_type_name" parameter raises a warning for the GET request
     */
    public void testIncludeTypeNamesWarning() throws IOException {
        Map<String, String> params = new HashMap<>();
        params.put(INCLUDE_TYPE_NAME_PARAMETER, randomFrom("true", "false"));
        RestRequest request = new FakeRestRequest.Builder(xContentRegistry())
            .withMethod(RestRequest.Method.GET)
            .withPath("/some_index")
            .build();

        RestGetIndicesAction handler = new RestGetIndicesAction(Settings.EMPTY, mock(RestController.class));
        handler.prepareRequest(request, mock(NodeClient.class));

        params = new HashMap<>();
        params.put(INCLUDE_TYPE_NAME_PARAMETER, randomFrom("true", "false"));

        RestRequest validRequest = new FakeRestRequest.Builder(xContentRegistry())
            .withMethod(RestRequest.Method.GET)
            .withPath("/some_index")
            .withParams(params)
            .build();
        handler.prepareRequest(validRequest, mock(NodeClient.class));
        assertWarnings(RestGetIndicesAction.TYPES_DEPRECATION_MESSAGE);
    }

    /**
     * Test that ommitting setting the "include_type_name" parameter doesn't raises a warning for HEAD method (indices.exists)
     */
    public void testIncludeTypeNamesWarningExists() throws IOException {
        Map<String, String> params = new HashMap<>();
        RestRequest request = new FakeRestRequest.Builder(xContentRegistry())
            .withMethod(RestRequest.Method.HEAD)
            .withPath("/some_index")
            .withParams(params)
            .build();

        RestGetIndicesAction handler = new RestGetIndicesAction(Settings.EMPTY, mock(RestController.class));
        handler.prepareRequest(request, mock(NodeClient.class));
    }
}
