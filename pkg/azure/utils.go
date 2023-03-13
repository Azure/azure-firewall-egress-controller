// -------------------------------------------------------------------------------------------
// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// --------------------------------------------------------------------------------------------

package controllers

func checkIfLabelExists(m1 []map[string]string, m2 map[string]string) bool {
	for _, m := range m1 {
		for k, v := range m {
			for k1, v1 := range m2 {
				if k1 == k && v1 == v {
					return true
				}
			}
		}
	}
	return false
}

func unique(arr []string) []string {
	occurred := map[string]bool{}
	result := []string{}
	for e := range arr {
		if occurred[arr[e]] != true {
			occurred[arr[e]] = true
			result = append(result, arr[e])
		}
	}
	return result
}
