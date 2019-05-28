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

package org.elasticsearch.index.fielddata.plain;

import org.apache.lucene.index.DocValues;
import org.apache.lucene.index.RandomAccessOrds;
import org.elasticsearch.index.fielddata.AtomicOrdinalsFieldData;
import org.elasticsearch.index.fielddata.FieldData;
import org.elasticsearch.index.fielddata.ScriptDocValues;
import org.elasticsearch.index.fielddata.SortedBinaryDocValues;


/**
 */
public abstract class AbstractAtomicOrdinalsFieldData implements AtomicOrdinalsFieldData {

    @Override
    public final ScriptDocValues getScriptValues() {
        return new ScriptDocValues.Strings(getBytesValues());
    }

    @Override
    public final SortedBinaryDocValues getBytesValues() {
        return FieldData.toString(getOrdinalsValues());
    }

    public static AtomicOrdinalsFieldData empty() {
        return new AbstractAtomicOrdinalsFieldData() {

            @Override
            public long ramBytesUsed() {
                return 0;
            }

            @Override
            public void close() {
            }

            @Override
            public RandomAccessOrds getOrdinalsValues() {
                return (RandomAccessOrds) DocValues.emptySortedSet();
            }
        };
    }
}