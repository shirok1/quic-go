package quic

import (
	"context"
	"errors"
	"fmt"
	"net"

	"github.com/quic-go/quic-go/internal/flowcontrol"
	"github.com/quic-go/quic-go/internal/mocks"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/wire"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func (e streamError) TestError() error {
	nums := make([]interface{}, len(e.nums))
	for i, num := range e.nums {
		nums[i] = num
	}
	return fmt.Errorf(e.message, nums...)
}

type streamMapping struct {
	firstIncomingBidiStream protocol.StreamID
	firstIncomingUniStream  protocol.StreamID
	firstOutgoingBidiStream protocol.StreamID
	firstOutgoingUniStream  protocol.StreamID
}

func expectTooManyStreamsError(err error) {
	ExpectWithOffset(1, err).To(MatchError(&StreamLimitReachedError{}))
	nerr, ok := err.(net.Error)
	ExpectWithOffset(1, ok).To(BeTrue())
	ExpectWithOffset(1, nerr.Timeout()).To(BeFalse())
	//nolint:staticcheck // SA1019
	// In older versions of quic-go, the stream limit error was documented to be a net.Error.Temporary.
	// This function was since deprecated, but we keep the existing behavior.
	ExpectWithOffset(1, nerr.Temporary()).To(BeTrue())
}

var _ = Describe("Streams Map", func() {
	newFlowController := func(protocol.StreamID) flowcontrol.StreamFlowController {
		return mocks.NewMockStreamFlowController(mockCtrl)
	}

	serverStreamMapping := streamMapping{
		firstIncomingBidiStream: 0,
		firstOutgoingBidiStream: 1,
		firstIncomingUniStream:  2,
		firstOutgoingUniStream:  3,
	}
	clientStreamMapping := streamMapping{
		firstIncomingBidiStream: 1,
		firstOutgoingBidiStream: 0,
		firstIncomingUniStream:  3,
		firstOutgoingUniStream:  2,
	}

	for _, p := range []protocol.Perspective{protocol.PerspectiveServer, protocol.PerspectiveClient} {
		perspective := p
		var ids streamMapping
		if perspective == protocol.PerspectiveClient {
			ids = clientStreamMapping
		} else {
			ids = serverStreamMapping
		}

		Context(perspective.String(), func() {
			var (
				m                   *streamsMap
				mockSender          *MockStreamSender
				queuedControlFrames []wire.Frame
			)

			const (
				MaxBidiStreamNum = 111
				MaxUniStreamNum  = 222
			)

			BeforeEach(func() {
				queuedControlFrames = []wire.Frame{}
				mockSender = NewMockStreamSender(mockCtrl)
				m = newStreamsMap(
					context.Background(),
					mockSender,
					func(f wire.Frame) { queuedControlFrames = append(queuedControlFrames, f) },
					newFlowController,
					MaxBidiStreamNum,
					MaxUniStreamNum,
					perspective,
				)
			})

			It("processes the parameter for outgoing streams", func() {
				_, err := m.OpenStream()
				expectTooManyStreamsError(err)
				m.UpdateLimits(&wire.TransportParameters{
					MaxBidiStreamNum: 5,
					MaxUniStreamNum:  8,
				})

				// test we can only 5 bidirectional streams
				for i := 0; i < 5; i++ {
					str, err := m.OpenStream()
					Expect(err).ToNot(HaveOccurred())
					Expect(str.StreamID()).To(Equal(ids.firstOutgoingBidiStream + protocol.StreamID(4*i)))
				}
				_, err = m.OpenStream()
				expectTooManyStreamsError(err)
				// test we can only 8 unidirectional streams
				for i := 0; i < 8; i++ {
					str, err := m.OpenUniStream()
					Expect(err).ToNot(HaveOccurred())
					Expect(str.StreamID()).To(Equal(ids.firstOutgoingUniStream + protocol.StreamID(4*i)))
				}
				_, err = m.OpenUniStream()
				expectTooManyStreamsError(err)
				Expect(queuedControlFrames).To(HaveLen(3))
			})

			if perspective == protocol.PerspectiveClient {
				It("applies parameters to existing streams (needed for 0-RTT)", func() {
					m.UpdateLimits(&wire.TransportParameters{
						MaxBidiStreamNum: 1000,
						MaxUniStreamNum:  1000,
					})
					flowControllers := make(map[protocol.StreamID]*mocks.MockStreamFlowController)
					m.newFlowController = func(id protocol.StreamID) flowcontrol.StreamFlowController {
						fc := mocks.NewMockStreamFlowController(mockCtrl)
						flowControllers[id] = fc
						return fc
					}

					str, err := m.OpenStream()
					Expect(err).ToNot(HaveOccurred())
					unistr, err := m.OpenUniStream()
					Expect(err).ToNot(HaveOccurred())

					Expect(flowControllers).To(HaveKey(str.StreamID()))
					flowControllers[str.StreamID()].EXPECT().UpdateSendWindow(protocol.ByteCount(4321))
					Expect(flowControllers).To(HaveKey(unistr.StreamID()))
					flowControllers[unistr.StreamID()].EXPECT().UpdateSendWindow(protocol.ByteCount(1234))

					m.UpdateLimits(&wire.TransportParameters{
						MaxBidiStreamNum:               1000,
						InitialMaxStreamDataUni:        1234,
						MaxUniStreamNum:                1000,
						InitialMaxStreamDataBidiRemote: 4321,
					})
				})
			}

			Context("handling MAX_STREAMS frames", func() {
				It("processes IDs for outgoing bidirectional streams", func() {
					_, err := m.OpenStream()
					expectTooManyStreamsError(err)
					m.HandleMaxStreamsFrame(&wire.MaxStreamsFrame{
						Type:         protocol.StreamTypeBidi,
						MaxStreamNum: 1,
					})
					str, err := m.OpenStream()
					Expect(err).ToNot(HaveOccurred())
					Expect(str.StreamID()).To(Equal(ids.firstOutgoingBidiStream))
					_, err = m.OpenStream()
					expectTooManyStreamsError(err)
				})

				It("processes IDs for outgoing unidirectional streams", func() {
					_, err := m.OpenUniStream()
					expectTooManyStreamsError(err)
					m.HandleMaxStreamsFrame(&wire.MaxStreamsFrame{
						Type:         protocol.StreamTypeUni,
						MaxStreamNum: 1,
					})
					str, err := m.OpenUniStream()
					Expect(err).ToNot(HaveOccurred())
					Expect(str.StreamID()).To(Equal(ids.firstOutgoingUniStream))
					_, err = m.OpenUniStream()
					expectTooManyStreamsError(err)
				})
			})

			It("closes", func() {
				testErr := errors.New("test error")
				m.CloseWithError(testErr)
				_, err := m.OpenStream()
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(Equal(testErr.Error()))
				_, err = m.OpenUniStream()
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(Equal(testErr.Error()))
				_, err = m.AcceptStream(context.Background())
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(Equal(testErr.Error()))
				_, err = m.AcceptUniStream(context.Background())
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(Equal(testErr.Error()))
			})

			if perspective == protocol.PerspectiveClient {
				It("resets for 0-RTT", func() {
					m.ResetFor0RTT()
					// make sure that calls to open / accept streams fail
					_, err := m.OpenStream()
					Expect(err).To(MatchError(Err0RTTRejected))
					_, err = m.AcceptStream(context.Background())
					Expect(err).To(MatchError(Err0RTTRejected))
					// make sure that we can still get new streams, as the server might be sending us data
					str, err := m.GetOrOpenReceiveStream(3)
					Expect(err).ToNot(HaveOccurred())
					Expect(str).ToNot(BeNil())

					// now switch to using the new streams map
					m.UseResetMaps()
					_, err = m.OpenStream()
					Expect(err).To(HaveOccurred())
					Expect(err.Error()).To(ContainSubstring("too many open streams"))
				})
			}
		})
	}
})
