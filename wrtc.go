package main

import (
	"fmt"
	"github.com/goccy/go-json"
	"github.com/pion/webrtc/v4"
	"strings"
)

func HandleWebRTCRequest(server *SyncRoomServer, s *SyncedSession, text string) {
	// Request needs to be in the format: KEY;VALUE
	data := strings.SplitN(text[8:], ";", 2)
	if len(data) != 2 {
		SendMsg(s, text, "[s:ERR]400;Payload Malformed")
		return
	}
	key := data[0]
	value := data[1]
	// Since we implement the WebRTC specifications, we simply listen for pre-defined messages
	switch key {
	case "ICE":
		err := AddPeerIceCandidate(s, value)
		if err != nil {
			SendMsg(s, text, "[s:ERR]500;Error Setting Peer ICE Candidate: "+err.Error())
			return
		}
		SendMsg(s, text, "[s:ANS]200;ICE Candidate Set")
		break
	case "OFFER":
		// Remote description received -> We add (or renegotiate) a peer connection
		peerCon, err := CreatePeerConnection(server, s)
		if err != nil {
			SendMsg(s, text, "[s:ERR]500;Error Creating Peer Connection: "+err.Error())
			return
		}
		err = AcceptPeerOffer(s, peerCon, value)
		if err != nil {
			SendMsg(s, text, "[s:ERR]500;Error Accepting Offer: "+err.Error())
			return
		}
		SendMsg(s, text, "[s:ANS]200;Offer Accepted")
		s.Mu.Lock()
		s.PeerCon = peerCon
		s.Mu.Unlock()
		break
	case "ANSWER":
		// Currently we discard answers sine the wikiric backend only receives offers by the wikiric frontend
		SendMsg(s, text, "[s:ERR]503;Service Unavailable")
		break
	case "DC":
		s.Mu.Lock()
		err := s.PeerCon.Close()
		if err != nil {
			SendMsg(s, text, "[s:ERR]500;Error Closing Peer Connection: "+err.Error())
			s.Mu.Unlock()
			return
		}
		SendMsg(s, text, "[s:ANS]200;Peer Connection Closed")
		s.PeerCon = nil
		s.Mu.Unlock()
		break
	}
}

func CreatePeerConnection(server *SyncRoomServer, s *SyncedSession) (*webrtc.PeerConnection, error) {
	iceServers := []webrtc.ICEServer{
		{
			URLs: []string{"stun:wikiric.xyz:3478"},
		},
		{
			URLs:       []string{"turn:wikiric.xyz:3478"},
			Username:   "wikiturnric",
			Credential: "turnipricwiki",
		},
	}

	/**
	  Original config taken from the wikiric frontend:

	  iceServers: [{
	      urls: ['stun:wikiric.xyz:3478']
	    }, {
	      urls: 'turn:wikiric.xyz:3478',
	      username: 'wikiturnric',
	      credential: 'turnipricwiki'
	    }],
	*/

	config := webrtc.Configuration{
		ICEServers: iceServers,
	}
	peerCon, err := webrtc.NewPeerConnection(config)
	if err != nil {
		return nil, err
	}
	candidates := make([]webrtc.ICECandidateInit, 0)
	peerCon.OnICECandidate(func(c *webrtc.ICECandidate) {
		var can webrtc.ICECandidateInit
		if c != nil {
			// We don't need to add a nil candidate
			// This just notifies us that no more candidates can be generated
			can = (*c).ToJSON()
			candidates = append(candidates, can)
		} else {
			// A nil candidate will be sent in form of an empty candidate
			// As of 13.11.2024 the wikiric backend works in the same way
			can = webrtc.ICECandidateInit{
				Candidate:        "",
				SDPMid:           nil,
				SDPMLineIndex:    nil,
				UsernameFragment: nil,
			}
		}
		canStr, err := JsonStringify(can)
		if err != nil {
			return
		}
		// Send back ICE candidate immediately, so we can sort out protocols faster
		msg := &SyncMessage{
			Text:     "",
			Username: s.User.Username,
			Action:   "[s:ICE]" + canStr,
		}
		s.Mu.RLock()
		_ = WSSendJSON(s.Conn, s.Ctx, msg)
		s.Mu.RUnlock()
	})
	// Handle incoming data channel from the wikiric frontend
	// As of 13.11.2024, channel created will have the following config:
	//
	// label = 'data'
	// channelDict = {
	//   negotiated: true,
	//   id: 0,
	//   ordered: true,
	//   maxRetransmits: 0
	// }
	peerCon.OnDataChannel(func(d *webrtc.DataChannel) {
		if d.Label() == "data" {
			d.OnOpen(func() {
				// Remember this data channel
				s.Mu.Lock()
				s.PeerData = d
				s.Mu.Unlock()
				// Notify client
				_ = d.SendText("wlcm")
				// Listen for messages
				// Since we only expect string messages sent, we check their type
				d.OnMessage(func(msg webrtc.DataChannelMessage) {
					if msg.IsString {
						content := string(msg.Data)
						// Check if message is a command, otherwise we will distribute that message to all other peers
						if CheckPrefix(content, "[c:") {
							handleDataChannelCommand(server, s, content)
						} else {
							DistributeDataChannelMessage(s, content)
						}
					}
				})
			})
			return
		}
	})
	return peerCon, nil
}

func handleDataChannelCommand(server *SyncRoomServer, s *SyncedSession, content string) {
	// TODO: Actually do something here
}

func DistributeDataChannelMessage(s *SyncedSession, content string) bool {
	room, ok := s.GetRoom()
	if !ok {
		return false
	}
	room.Mu.RLock()
	defer room.Mu.RUnlock()
	var dchan *webrtc.DataChannel
	var err error
	count := 0
	for _, peer := range room.Sessions {
		if peer.User.Username == s.User.Username {
			// Do not distribute a message to the sender itself
			continue
		}
		dchan, ok = peer.GetDatachannel()
		if !ok {
			// Avoid trying to send messages to channels that are not ready yet
			continue
		}
		err = dchan.SendText(content)
		if err != nil {
			continue
		}
		count += 1
	}
	return count > 0
}

func AcceptPeerOffer(s *SyncedSession, peerCon *webrtc.PeerConnection, offerJson string) error {
	if peerCon == nil {
		return fmt.Errorf("no peer connection")
	}
	offer := webrtc.SessionDescription{}
	err := json.Unmarshal([]byte(offerJson), &offer)
	if err != nil {
		return fmt.Errorf("could not parse remote description: %w", err)
	}
	if err = peerCon.SetRemoteDescription(offer); err != nil {
		return fmt.Errorf("could not set remote description: %w", err)
	}
	answer, err := peerCon.CreateAnswer(nil)
	if err != nil {
		return fmt.Errorf("could not create answer: %w", err)
	}
	err = peerCon.SetLocalDescription(answer)
	if err != nil {
		return fmt.Errorf("could not set local description: %w", err)
	}
	locStr, err := JsonStringify(peerCon.LocalDescription())
	if err != nil {
		return fmt.Errorf("could not parse local description: %w", err)
	}
	// Send back ICE candidate immediately, so we can sort out protocols faster
	msg := &SyncMessage{
		Text:     "",
		Username: s.User.Username,
		Action:   "[s:ANSWER]" + locStr,
	}
	_ = WSSendJSON(s.Conn, s.Ctx, msg)
	return nil
}

func AddPeerIceCandidate(s *SyncedSession, candidateJson string) error {
	s.Mu.Lock()
	defer s.Mu.Unlock()
	candidate := webrtc.ICECandidateInit{}
	err := json.Unmarshal([]byte(candidateJson), &candidate)
	if err != nil {
		return fmt.Errorf("could not parse remote description: %w", err)
	}
	if s.PeerCon == nil {
		return fmt.Errorf("no peer connection")
	}
	if err = s.PeerCon.AddICECandidate(candidate); err != nil {
		return fmt.Errorf("could not add ice candidate: %w", err)
	}
	return nil
}

func (s *SyncedSession) GetDatachannel() (*webrtc.DataChannel, bool) {
	s.Mu.RLock()
	defer s.Mu.RUnlock()
	if s.PeerData == nil {
		return nil, false
	}
	return s.PeerData, true
}
