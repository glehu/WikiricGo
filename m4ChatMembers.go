package main

import (
	"encoding/json"
	"fmt"
	"slices"
	"sort"
)

const MemberDB = "m4"

type ChatMemberList struct {
	ChatMembers []*ChatMember `json:"members"`
}

type ChatMemberEntry struct {
	*ChatMember
	UUID string `json:"uid"`
}

type ChatMember struct {
	Username             string   `json:"usr"`
	ChatGroupUUID        string   `json:"parent"`
	DisplayName          string   `json:"name"`
	Roles                []string `json:"roles"`
	PublicKey            string   `json:"pubkey"`
	ThumbnailURL         string   `json:"iurl"`
	ThumbnailAnimatedURL string   `json:"iurla"`
	BannerURL            string   `json:"burl"`
	BannerAnimatedURL    string   `json:"burla"`
	FCMToken             string   `json:"fcm"`
	DateCreated          string   `json:"ts"`
}

func (member *ChatMember) GetRoleInformation(group *ChatGroup) *ChatRole {
	var userRole *ChatRole
	// Get all roles of the provided chat group and sort them
	groupRoles := group.Roles
	sort.Slice(groupRoles, func(i, j int) bool {
		return groupRoles[i].Index < groupRoles[j].Index
	})
	// Iterate from the highest ranking role to the lowest one
	var ix int
	for _, role := range groupRoles {
		ix = slices.Index(member.Roles, role.Name)
		if ix != -1 {
			// Role found
			if userRole == nil {
				tmp := role
				userRole = &tmp
			}
			if role.IsAdmin {
				userRole.IsAdmin = true
			}
		}
	}
	return userRole
}

func (db *GoDB) CheckFriendGroupExist(selfUser, friendUser string) (string, error) {
	query := fmt.Sprintf("%s;%s", selfUser, friendUser)
	resp, err := db.Select(MemberDB, map[string]string{
		"user-friend": query,
	}, &SelectOptions{
		MaxResults: 1,
		Page:       0,
		Skip:       0,
	})
	if err != nil {
		return "", err
	}
	response := <-resp
	if len(response) < 1 {
		return "", nil
	}
	member := &ChatMember{}
	err = json.Unmarshal(response[0].Data, member)
	if err != nil {
		return "", err
	}
	return member.ChatGroupUUID, nil
}
