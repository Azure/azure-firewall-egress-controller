// -------------------------------------------------------------------------------------------
// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// --------------------------------------------------------------------------------------------

package controllers

func checkIfLabelExists(k string, v string, m2 map[string]string) bool {
	for k1, v1 := range m2 {
		if k1 == k && v1 == v {
			return true
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

func checkIfElementsPresentInArray(arr1 []*string, arr2 []*string) bool {
	newElementFound := false
	for _, ele1 := range arr1 {
		found := false
		for _, ele2 := range arr2 {
			if *ele1 == *ele2 {
				found = true
				break
			}
		}
		if found == false {
			newElementFound = true
		}
	}
	return newElementFound
}
