package quic

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/quic-go/quic-go/internal/flowcontrol"
	"github.com/quic-go/quic-go/internal/mocks"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/qerr"
	"github.com/quic-go/quic-go/internal/wire"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

const (
	firstIncomingBidiStreamServer protocol.StreamID = 0
	firstOutgoingBidiStreamServer protocol.StreamID = 1
	firstIncomingUniStreamServer  protocol.StreamID = 2
	firstOutgoingUniStreamServer  protocol.StreamID = 3
)

const (
	firstIncomingBidiStreamClient protocol.StreamID = 1
	firstOutgoingBidiStreamClient protocol.StreamID = 0
	firstIncomingUniStreamClient  protocol.StreamID = 3
	firstOutgoingUniStreamClient  protocol.StreamID = 2
)

func TestStreamsMapCreatingStreams(t *testing.T) {
	t.Run("client", func(t *testing.T) {
		testStreamsMapCreatingAndDeletingStreams(t, protocol.PerspectiveClient,
			firstIncomingBidiStreamClient,
			firstOutgoingBidiStreamClient,
			firstIncomingUniStreamClient,
			firstOutgoingUniStreamClient,
		)
	})
	t.Run("server", func(t *testing.T) {
		testStreamsMapCreatingAndDeletingStreams(t, protocol.PerspectiveServer,
			firstIncomingBidiStreamServer,
			firstOutgoingBidiStreamServer,
			firstIncomingUniStreamServer,
			firstOutgoingUniStreamServer,
		)
	})
}

func testStreamsMapCreatingAndDeletingStreams(t *testing.T,
	perspective protocol.Perspective,
	firstIncomingBidiStream protocol.StreamID,
	firstOutgoingBidiStream protocol.StreamID,
	firstIncomingUniStream protocol.StreamID,
	firstOutgoingUniStream protocol.StreamID,
) {
	mockCtrl := gomock.NewController(t)
	mockSender := NewMockStreamSender(mockCtrl)
	m := newStreamsMap(
		context.Background(),
		mockSender,
		func(wire.Frame) {},
		func(protocol.StreamID) flowcontrol.StreamFlowController {
			return mocks.NewMockStreamFlowController(mockCtrl)
		},
		1,
		1,
		perspective,
	)
	m.UpdateLimits(&wire.TransportParameters{
		MaxBidiStreamNum: protocol.MaxStreamCount,
		MaxUniStreamNum:  protocol.MaxStreamCount,
	})

	// opening streams
	str1, err := m.OpenStream()
	require.NoError(t, err)
	str2, err := m.OpenStream()
	require.NoError(t, err)
	ustr1, err := m.OpenUniStream()
	require.NoError(t, err)
	ustr2, err := m.OpenUniStream()
	require.NoError(t, err)

	assert.Equal(t, str1.StreamID(), firstOutgoingBidiStream)
	assert.Equal(t, str2.StreamID(), firstOutgoingBidiStream+4)
	assert.Equal(t, ustr1.StreamID(), firstOutgoingUniStream)
	assert.Equal(t, ustr2.StreamID(), firstOutgoingUniStream+4)

	// accepting streams:
	// This function is called when a frame referencing this stream is received.
	// The peer may open a peer-initiated stream...
	_, err = m.GetOrOpenReceiveStream(firstIncomingBidiStream)
	require.NoError(t, err)
	_, err = m.GetOrOpenReceiveStream(firstIncomingUniStream)
	require.NoError(t, err)

	// ... but not a stream that is initiated by us.
	_, err = m.GetOrOpenSendStream(firstOutgoingBidiStream + 8)
	require.ErrorIs(t, err, &qerr.TransportError{
		ErrorCode:    qerr.StreamStateError,
		ErrorMessage: fmt.Sprintf("peer attempted to open stream %d", firstOutgoingBidiStream+8),
	})
	_, err = m.GetOrOpenSendStream(firstOutgoingUniStream + 8)
	require.ErrorIs(t, err, &qerr.TransportError{
		ErrorCode:    qerr.StreamStateError,
		ErrorMessage: fmt.Sprintf("peer attempted to open stream %d", firstOutgoingUniStream+8),
	})

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	str, err := m.AcceptStream(ctx)
	require.NoError(t, err)
	ustr, err := m.AcceptUniStream(ctx)
	require.NoError(t, err)

	assert.Equal(t, str.StreamID(), firstIncomingBidiStream)
	assert.Equal(t, ustr.StreamID(), firstIncomingUniStream)
}

func TestStreamsMapDeletingStreams(t *testing.T) {
	t.Run("client", func(t *testing.T) {
		testStreamsMapDeletingStreams(t, protocol.PerspectiveClient,
			firstIncomingBidiStreamClient,
			firstOutgoingBidiStreamClient,
			firstIncomingUniStreamClient,
			firstOutgoingUniStreamClient,
		)
	})
	t.Run("server", func(t *testing.T) {
		testStreamsMapDeletingStreams(t, protocol.PerspectiveServer,
			firstIncomingBidiStreamServer,
			firstOutgoingBidiStreamServer,
			firstIncomingUniStreamServer,
			firstOutgoingUniStreamServer,
		)
	})
}

func testStreamsMapDeletingStreams(t *testing.T,
	perspective protocol.Perspective,
	firstIncomingBidiStream protocol.StreamID,
	firstOutgoingBidiStream protocol.StreamID,
	firstIncomingUniStream protocol.StreamID,
	firstOutgoingUniStream protocol.StreamID,
) {
	mockCtrl := gomock.NewController(t)
	mockSender := NewMockStreamSender(mockCtrl)
	var frameQueue []wire.Frame
	m := newStreamsMap(
		context.Background(),
		mockSender,
		func(frame wire.Frame) { frameQueue = append(frameQueue, frame) },
		func(protocol.StreamID) flowcontrol.StreamFlowController {
			return mocks.NewMockStreamFlowController(mockCtrl)
		},
		100,
		100,
		perspective,
	)
	m.UpdateLimits(&wire.TransportParameters{
		MaxBidiStreamNum: 10,
		MaxUniStreamNum:  10,
	})

	_, err := m.OpenStream()
	require.NoError(t, err)
	require.NoError(t, m.DeleteStream(firstOutgoingBidiStream))
	sstr, err := m.GetOrOpenSendStream(firstOutgoingBidiStream)
	require.NoError(t, err)
	require.Nil(t, sstr)
	require.ErrorContains(t,
		m.DeleteStream(firstOutgoingBidiStream+400),
		fmt.Sprintf("tried to delete unknown outgoing stream %d", firstOutgoingBidiStream+400),
	)

	_, err = m.OpenUniStream()
	require.NoError(t, err)
	require.NoError(t, m.DeleteStream(firstOutgoingUniStream))
	sstr, err = m.GetOrOpenSendStream(firstOutgoingUniStream)
	require.NoError(t, err)
	require.Nil(t, sstr)
	require.ErrorContains(t,
		m.DeleteStream(firstOutgoingUniStream+400),
		fmt.Sprintf("tried to delete unknown outgoing stream %d", firstOutgoingUniStream+400),
	)

	require.Empty(t, frameQueue)
	// deleting incoming bidirectional streams
	_, err = m.GetOrOpenReceiveStream(firstIncomingBidiStream)
	require.NoError(t, err)
	require.NoError(t, m.DeleteStream(firstIncomingBidiStream))
	sstr, err = m.GetOrOpenSendStream(firstIncomingBidiStream)
	require.NoError(t, err)
	require.Nil(t, sstr)
	require.ErrorContains(t,
		m.DeleteStream(firstIncomingBidiStream+400),
		fmt.Sprintf("tried to delete unknown incoming stream %d", firstIncomingBidiStream+400),
	)
	// the MAX_STREAMS frame is only queued once the stream is accepted
	require.Empty(t, frameQueue)
	_, err = m.AcceptStream(context.Background())
	require.NoError(t, err)

	require.Equal(t, frameQueue, []wire.Frame{
		&wire.MaxStreamsFrame{
			Type:         protocol.StreamTypeBidi,
			MaxStreamNum: 101,
		},
	})
	frameQueue = frameQueue[:0]

	// deleting incoming unidirectional streams
	_, err = m.GetOrOpenReceiveStream(firstIncomingUniStream)
	require.NoError(t, err)
	require.NoError(t, m.DeleteStream(firstIncomingUniStream))
	rstr, err := m.GetOrOpenReceiveStream(firstIncomingUniStream)
	require.NoError(t, err)
	require.Nil(t, rstr)
	require.ErrorContains(t,
		m.DeleteStream(firstIncomingUniStream+400),
		fmt.Sprintf("tried to delete unknown incoming stream %d", firstIncomingUniStream+400),
	)
	// the MAX_STREAMS frame is only queued once the stream is accepted
	require.Empty(t, frameQueue)
	_, err = m.AcceptUniStream(context.Background())
	require.NoError(t, err)

	require.Equal(t, frameQueue, []wire.Frame{
		&wire.MaxStreamsFrame{
			Type:         protocol.StreamTypeUni,
			MaxStreamNum: 101,
		},
	})
	frameQueue = frameQueue[:0]
}
