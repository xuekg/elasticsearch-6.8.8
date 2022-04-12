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

package org.elasticsearch.search;

import org.apache.lucene.search.SortField;
import org.apache.lucene.util.TestUtil;
import org.elasticsearch.Version;
import org.elasticsearch.action.OriginalIndices;
import org.elasticsearch.common.Strings;
import org.elasticsearch.common.bytes.BytesReference;
import org.elasticsearch.common.io.stream.StreamInput;
import org.elasticsearch.common.lucene.LuceneTests;
import org.elasticsearch.common.text.Text;
import org.elasticsearch.common.xcontent.LoggingDeprecationHandler;
import org.elasticsearch.common.xcontent.ToXContent;
import org.elasticsearch.common.xcontent.XContentBuilder;
import org.elasticsearch.common.xcontent.XContentParser;
import org.elasticsearch.common.xcontent.XContentType;
import org.elasticsearch.common.xcontent.json.JsonXContent;
import org.elasticsearch.index.Index;
import org.elasticsearch.index.shard.ShardId;
import org.elasticsearch.test.AbstractStreamableXContentTestCase;
import org.elasticsearch.test.VersionUtils;

import java.io.IOException;
import java.util.Base64;
import java.util.Collections;
import java.util.function.Predicate;

public class SearchHitsTests extends AbstractStreamableXContentTestCase<SearchHits> {

    public static SearchHits createTestItem(boolean withOptionalInnerHits, boolean withShardTarget) {
        return createTestItem(randomFrom(XContentType.values()), withOptionalInnerHits, withShardTarget);
    }

    private static SearchHit[] createSearchHitArray(int size, XContentType xContentType, boolean withOptionalInnerHits,
                                                    boolean transportSerialization) {
        SearchHit[] hits = new SearchHit[size];
        for (int i = 0; i < hits.length; i++) {
            hits[i] = SearchHitTests.createTestItem(xContentType, withOptionalInnerHits, transportSerialization);
        }
        return hits;
    }

    public static SearchHits createTestItem(XContentType xContentType, boolean withOptionalInnerHits, boolean transportSerialization) {
        int searchHits = randomIntBetween(0, 5);
        SearchHit[] hits = createSearchHitArray(searchHits, xContentType, withOptionalInnerHits, transportSerialization);
        float maxScore = frequently() ? randomFloat() : Float.NaN;
        long totalHits = TestUtil.nextLong(random(), 0, Long.MAX_VALUE);
        SortField[] sortFields = null;
        String collapseField = null;
        Object[] collapseValues = null;
        if (transportSerialization) {
            sortFields = randomBoolean() ? createSortFields(randomIntBetween(1, 5)) : null;
            collapseField = randomAlphaOfLengthBetween(5, 10);
            collapseValues = randomBoolean() ? createCollapseValues(randomIntBetween(1, 10)) : null;
        }
        return new SearchHits(hits, totalHits, maxScore, sortFields, collapseField, collapseValues);
    }

    private static SortField[] createSortFields(int size) {
        SortField[] sortFields = new SortField[size];
        for (int i = 0; i < sortFields.length; i++) {
            //sort fields are simplified before serialization, we write directly the simplified version
            //otherwise equality comparisons become complicated
            sortFields[i] = LuceneTests.randomSortField().v2();
        }
        return sortFields;
    }

    private static Object[] createCollapseValues(int size) {
        Object[] collapseValues = new Object[size];
        for (int i = 0; i < collapseValues.length; i++) {
            collapseValues[i] = LuceneTests.randomSortValue();
        }
        return collapseValues;
    }

    @Override
    protected SearchHits mutateInstance(SearchHits instance) {
        switch (randomIntBetween(0, 5)) {
            case 0:
                return new SearchHits(createSearchHitArray(instance.getHits().length + 1,
                    randomFrom(XContentType.values()), false, randomBoolean()),
                    instance.getTotalHits(), instance.getMaxScore());
            case 1:
                long totalHits = instance.getTotalHits() == -1 ? TestUtil.nextLong(random(), 0, Long.MAX_VALUE) : -1;
                return new SearchHits(instance.getHits(), totalHits, instance.getMaxScore());
            case 2:
                final float maxScore;
                if (Float.isNaN(instance.getMaxScore())) {
                    maxScore = randomFloat();
                } else {
                    maxScore = Float.NaN;
                }
                return new SearchHits(instance.getHits(), instance.getTotalHits(), maxScore);
            case 3:
                SortField[] sortFields;
                if (instance.getSortFields() == null) {
                    sortFields = createSortFields(randomIntBetween(1, 5));
                } else {
                    sortFields = randomBoolean() ? createSortFields(instance.getSortFields().length + 1) : null;
                }
                return new SearchHits(instance.getHits(), instance.getTotalHits(), instance.getMaxScore(),
                    sortFields, instance.getCollapseField(), instance.getCollapseValues());
            case 4:
                String collapseField;
                if (instance.getCollapseField() == null) {
                    collapseField = randomAlphaOfLengthBetween(5, 10);
                } else {
                    collapseField = randomBoolean() ? instance.getCollapseField() + randomAlphaOfLengthBetween(2, 5) : null;
                }
                return new SearchHits(instance.getHits(), instance.getTotalHits(), instance.getMaxScore(),
                    instance.getSortFields(), collapseField, instance.getCollapseValues());
            case 5:
                Object[] collapseValues;
                if (instance.getCollapseValues() == null) {
                    collapseValues = createCollapseValues(randomIntBetween(1, 5));
                } else {
                    collapseValues = randomBoolean() ? createCollapseValues(instance.getCollapseValues().length + 1) : null;
                }
                return new SearchHits(instance.getHits(), instance.getTotalHits(), instance.getMaxScore(),
                    instance.getSortFields(), instance.getCollapseField(), collapseValues);
            default:
                throw new UnsupportedOperationException();
        }
    }

    @Override
    protected Predicate<String> getRandomFieldsExcludeFilter() {
        return path -> (path.isEmpty() ||
            path.contains("inner_hits") || path.contains("highlight") || path.contains("fields") || path.contains("_source"));
    }

    @Override
    protected String[] getShuffleFieldsExceptions() {
        return new String[] {"_source"};
    }

    @Override
    protected SearchHits createBlankInstance() {
        return new SearchHits();
    }

    @Override
    protected SearchHits createTestInstance() {
        // This instance is used to test the transport serialization so it's fine
        // to produce shard targets (withShardTarget is true) since they are serialized
        // in this layer.
        return createTestItem(randomFrom(XContentType.values()), true, true);
    }

    @Override
    protected SearchHits createXContextTestInstance(XContentType xContentType) {
        // We don't set SearchHit#shard (withShardTarget is false) in this test
        // because the rest serialization does not render this information so the
        // deserialized hit cannot be equal to the original instance.
        // There is another test (#testFromXContentWithShards) that checks the
        // rest serialization with shard targets.
        return createTestItem(xContentType, true, false);
    }

    @Override
    protected SearchHits doParseInstance(XContentParser parser) throws IOException {
        assertEquals(XContentParser.Token.START_OBJECT, parser.nextToken());
        assertEquals(XContentParser.Token.FIELD_NAME, parser.nextToken());
        assertEquals(SearchHits.Fields.HITS, parser.currentName());
        assertEquals(XContentParser.Token.START_OBJECT, parser.nextToken());
        SearchHits searchHits = SearchHits.fromXContent(parser);
        assertEquals(XContentParser.Token.END_OBJECT, parser.currentToken());
        assertEquals(XContentParser.Token.END_OBJECT, parser.nextToken());
        return searchHits;
    }

    public void testToXContent() throws IOException {
        SearchHit[] hits = new SearchHit[] {
            new SearchHit(1, "id1", new Text("type"), Collections.emptyMap()),
            new SearchHit(2, "id2", new Text("type"), Collections.emptyMap()) };

        long totalHits = 1000;
        float maxScore = 1.5f;
        SearchHits searchHits = new SearchHits(hits, totalHits, maxScore);
        XContentBuilder builder = JsonXContent.contentBuilder();
        builder.startObject();
        searchHits.toXContent(builder, ToXContent.EMPTY_PARAMS);
        builder.endObject();
        assertEquals("{\"hits\":{\"total\":1000,\"max_score\":1.5," +
            "\"hits\":[{\"_type\":\"type\",\"_id\":\"id1\",\"_score\":\"-Infinity\"},"+
            "{\"_type\":\"type\",\"_id\":\"id2\",\"_score\":\"-Infinity\"}]}}", Strings.toString(builder));
    }

    public void testFromXContentWithShards() throws IOException {
        for (boolean withExplanation : new boolean[] {true, false}) {
            final SearchHit[] hits = new SearchHit[]{
                new SearchHit(1, "id1", new Text("type"), Collections.emptyMap()),
                new SearchHit(2, "id2", new Text("type"), Collections.emptyMap()),
                new SearchHit(10, "id10", new Text("type"), Collections.emptyMap())
            };

            for (SearchHit hit : hits) {
                String index = randomAlphaOfLengthBetween(5, 10);
                String clusterAlias = randomBoolean() ? null : randomAlphaOfLengthBetween(5, 10);
                final SearchShardTarget shardTarget = new SearchShardTarget(randomAlphaOfLengthBetween(5, 10),
                    new ShardId(new Index(index, randomAlphaOfLengthBetween(5, 10)), randomInt()), clusterAlias, OriginalIndices.NONE);
                if (withExplanation) {
                    hit.explanation(SearchHitTests.createExplanation(randomIntBetween(0, 5)));
                }
                hit.shard(shardTarget);
            }

            long totalHits = 1000;
            float maxScore = 1.5f;
            SearchHits searchHits = new SearchHits(hits, totalHits, maxScore);
            XContentType xContentType = randomFrom(XContentType.values());
            BytesReference bytes = toShuffledXContent(searchHits, xContentType, ToXContent.EMPTY_PARAMS, false);
            try (XContentParser parser = xContentType.xContent()
                    .createParser(xContentRegistry(), LoggingDeprecationHandler.INSTANCE, bytes.streamInput())) {
                SearchHits newSearchHits = doParseInstance(parser);
                assertEquals(3, newSearchHits.getHits().length);
                assertEquals("id1", newSearchHits.getAt(0).getId());
                for (int i = 0; i < hits.length; i++) {
                    assertEquals(hits[i].getExplanation(), newSearchHits.getAt(i).getExplanation());
                    if (withExplanation) {
                        assertEquals(hits[i].getShard().getIndex(), newSearchHits.getAt(i).getShard().getIndex());
                        assertEquals(hits[i].getShard().getShardId().getId(), newSearchHits.getAt(i).getShard().getShardId().getId());
                        assertEquals(hits[i].getShard().getShardId().getIndexName(),
                            newSearchHits.getAt(i).getShard().getShardId().getIndexName());
                        assertEquals(hits[i].getShard().getNodeId(), newSearchHits.getAt(i).getShard().getNodeId());
                        // The index uuid is not serialized in the rest layer
                        assertNotEquals(hits[i].getShard().getShardId().getIndex().getUUID(),
                            newSearchHits.getAt(i).getShard().getShardId().getIndex().getUUID());
                    } else {
                        assertNull(newSearchHits.getAt(i).getShard());
                    }
                }
            }

        }
    }

    public void testReadFromPre6_6_0() throws IOException {
        try (StreamInput in = StreamInput.wrap(Base64.getDecoder().decode("AQC/gAAAAAA="))) {
            in.setVersion(VersionUtils.randomVersionBetween(random(), Version.V_6_0_0, VersionUtils.getPreviousVersion(Version.V_6_6_0)));
            SearchHits searchHits = new SearchHits();
            searchHits.readFrom(in);
            assertEquals(0, searchHits.getHits().length);
            assertEquals(0L, searchHits.getTotalHits());
            assertEquals(-1F, searchHits.getMaxScore(), 0F);
            assertNull(searchHits.getSortFields());
            assertNull(searchHits.getCollapseField());
            assertNull(searchHits.getCollapseValues());
        }
    }

    public void testSerializationPre6_6_0() throws IOException {
        Version version = VersionUtils.randomVersionBetween(random(), Version.V_6_0_0, VersionUtils.getPreviousVersion(Version.V_6_6_0));
        SearchHits original = createTestItem(randomFrom(XContentType.values()), false, true);
        SearchHits deserialized = copyInstance(original, version);
        assertArrayEquals(original.getHits(), deserialized.getHits());
        assertEquals(original.getMaxScore(), deserialized.getMaxScore(), 0F);
        assertEquals(original.getTotalHits(), deserialized.getTotalHits());
        assertNull(deserialized.getSortFields());
        assertNull(deserialized.getCollapseField());
        assertNull(deserialized.getCollapseValues());
    }
}