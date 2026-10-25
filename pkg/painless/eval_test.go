// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package painless

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestEvalPainless_OpenMetadataTagAndSoftDeleteMutations(t *testing.T) {
	initial := `{"name":"orders","deleted":false,"updatedAt":1729773296789,"tier":{"tagFQN":"Tier.Tier2"},"tags":[{"tagFQN":"PII.Sensitive"},{"tagFQN":"Legacy"}],"followers":["u1","u2"]}`

	req := &UpdateRequest{
		Script: &ScriptSpec{
			Source: `
				ctx._source.deleted = params.deleted;
				ctx._source.remove('tier');
				ctx._source.tags.removeIf(t -> t.tagFQN == params.removeTag);
				if (ctx._source.tags == null) { ctx._source.tags = []; }
				if (!ctx._source.tags.contains(params.newTag)) {
					ctx._source.tags.add(params.newTag);
				}
				ctx._source.followers.removeIf(u -> u == params.removeFollower);
			`,
			Params: map[string]any{
				"deleted":        true,
				"removeTag":      "Legacy",
				"newTag":         map[string]any{"tagFQN": "Tier.Tier1"},
				"removeFollower": "u1",
			},
		},
	}

	updatedBytes, err := ApplyUpdate(json.RawMessage(initial), req)
	if err != nil {
		t.Fatalf("ApplyUpdate failed: %v", err)
	}
	// Verify 13-digit epoch timestamp was not corrupted into scientific notation
	if !strings.Contains(string(updatedBytes), `"updatedAt":1729773296789`) {
		t.Errorf("expected exact updatedAt integer in JSON, got %s", string(updatedBytes))
	}

	var out map[string]any
	if err := json.Unmarshal(updatedBytes, &out); err != nil {
		t.Fatalf("failed to unmarshal updated doc: %v", err)
	}

	if out["deleted"] != true {
		t.Errorf("expected deleted=true, got %v", out["deleted"])
	}
	if _, hasTier := out["tier"]; hasTier {
		t.Errorf("expected tier to be removed, still present: %v", out["tier"])
	}
	tags, ok := out["tags"].([]any)
	if !ok || len(tags) != 2 {
		t.Fatalf("expected 2 tags after removeIf + add, got %+v", out["tags"])
	}
	followers, ok := out["followers"].([]any)
	if !ok || len(followers) != 1 || followers[0] != "u2" {
		t.Fatalf("expected followers [u2] after scalar removeIf, got %+v", out["followers"])
	}
}
