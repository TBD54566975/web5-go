package jwt_test

// func TestClaims_MarshalJSON(t *testing.T) {
// 	claims := jwt.Claims{
// 		Issuer:  "issuer",
// 		Private: map[string]interface{}{"foo": "bar"},
// 	}

// 	b, err := json.Marshal(&claims)
// 	if err != nil {
// 		t.Fatal(err)
// 	}

// 	obj := make(map[string]interface{})
// 	if err := json.Unmarshal(b, &obj); err != nil {
// 		t.Fatal(err)
// 	}

// 	if obj["iss"] != "issuer" {
// 		t.Errorf("expected iss to be 'issuer', got %v", obj["iss"])
// 	}

// 	if obj["foo"] == nil {
// 		t.Errorf("expected foo to not be nil")
// 	}
// }
