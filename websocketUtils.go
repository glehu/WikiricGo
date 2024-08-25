package main

import (
	"bytes"
	"context"
	"encoding/json"
	"nhooyr.io/websocket"
)

func WSSendJSON(
	c *websocket.Conn,
	ctx context.Context,
	v interface{},
) error {
	buf := &bytes.Buffer{}
	enc := json.NewEncoder(buf)
	enc.SetEscapeHTML(true)
	if err := enc.Encode(v); err != nil {
		return err
	}
	err := c.Write(
		ctx,
		websocket.MessageText,
		buf.Bytes(),
	)
	if err != nil {
		return err
	}
	return nil
}

func WSSendBytes(
	c *websocket.Conn,
	ctx context.Context,
	b []byte,
) error {
	err := c.Write(
		ctx,
		websocket.MessageText,
		b,
	)
	if err != nil {
		return err
	}
	return nil
}
