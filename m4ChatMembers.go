package main

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
}

func OpenChatMemberDatabase() *GoDB {
	db := OpenDB(
		"chatMembers", []string{
			"chat-user",
		},
	)
	return db
}
