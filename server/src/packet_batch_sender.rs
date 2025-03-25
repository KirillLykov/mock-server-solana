//! Adapted from agave as it is, commented some unnecessary code.
use {
    crate::packet_accumulator::PacketAccumulator,
    async_channel::Receiver as AsyncReceiver,
    crossbeam_channel::Sender as CrossbeamSender,
    lazy_static::lazy_static,
    rand::Rng,
    solana_sdk::{
        packet::{Packet, PacketFlags},
        signature::SIGNATURE_BYTES,
    },
    solana_streamer::packet::{PacketBatch, PACKETS_PER_BATCH},
    std::convert::TryFrom,
    tokio::time::{timeout, Duration, Instant},
    tokio_util::sync::CancellationToken,
    tracing::{trace, warn},
};

#[derive(Debug, PartialEq, Eq)]
pub enum PacketError {
    InvalidLen,
    InvalidPubkeyLen,
    InvalidShortVec,
    InvalidSignatureLen,
    MismatchSignatureLen,
    PayerNotWritable,
    InvalidProgramIdIndex,
    InvalidProgramLen,
    UnsupportedVersion,
}

// The mask is 12 bits long (1<<12 = 4096), it means the probability of matching
// the transaction is 1/4096 assuming the portion being matched is random.
lazy_static! {
    static ref TXN_MASK: u16 = rand::thread_rng().gen_range(0..4096);
}

/// Check if a transaction given its signature matches the randomly selected mask.
/// The signaure should be from the reference of Signature
pub fn should_track_transaction(signature: &[u8; SIGNATURE_BYTES]) -> bool {
    // We do not use the highest signature byte as it is not really random
    let match_portion: u16 = u16::from_le_bytes([signature[61], signature[62]]) >> 4;
    *TXN_MASK == match_portion
}

/// Check if a transaction packet's signature matches the mask.
/// This does a rudimentry verification to make sure the packet at least
/// contains the signature data and it returns the reference to the signature.
pub fn signature_if_should_track_packet(
    packet: &Packet,
) -> Result<Option<&[u8; SIGNATURE_BYTES]>, PacketError> {
    let signature = get_signature_from_packet(packet)?;
    Ok(should_track_transaction(signature).then_some(signature))
}

/// Get the signature of the transaction packet
/// This does a rudimentry verification to make sure the packet at least
/// contains the signature data and it returns the reference to the signature.
pub fn get_signature_from_packet(packet: &Packet) -> Result<&[u8; SIGNATURE_BYTES], PacketError> {
    let (sig_len_untrusted, sig_start) = packet
        .data(..)
        .and_then(|bytes| decode_shortu16_len(bytes).ok())
        .ok_or(PacketError::InvalidShortVec)?;

    if sig_len_untrusted < 1 {
        return Err(PacketError::InvalidSignatureLen);
    }

    let signature = packet
        .data(sig_start..sig_start.saturating_add(SIGNATURE_BYTES))
        .ok_or(PacketError::InvalidSignatureLen)?;
    let signature = signature
        .try_into()
        .map_err(|_| PacketError::InvalidSignatureLen)?;
    Ok(signature)
}

// Holder(s) of the AsyncSender<PacketAccumulator> on the other end should not
// wait for this function to exit to exit
pub async fn packet_batch_sender(
    packet_sender: CrossbeamSender<PacketBatch>,
    packet_receiver: AsyncReceiver<PacketAccumulator>,
    token: CancellationToken,
    coalesce: Duration,
) {
    let mut batch_start_time = Instant::now();
    loop {
        //let mut packet_perf_measure: Vec<([u8; 64], Instant)> = Vec::default();
        let mut packet_batch = PacketBatch::with_capacity(PACKETS_PER_BATCH);
        let mut total_bytes: usize = 0;

        loop {
            // Instead of checking this flag, I check token.
            //if exit.load(Ordering::Relaxed) {
            //    return;
            //}
            if token.is_cancelled() {
                return;
            }
            let elapsed = batch_start_time.elapsed();
            if packet_batch.len() >= PACKETS_PER_BATCH
                || (!packet_batch.is_empty() && elapsed >= coalesce)
            {
                let len = packet_batch.len();
                //track_streamer_fetch_packet_performance(&packet_perf_measure, &stats);

                if let Err(e) = packet_sender.send(packet_batch) {
                    //    stats
                    //        .total_packet_batch_send_err
                    //        .fetch_add(1, Ordering::Relaxed);
                    warn!("Send error: {}", e); // TODO(klykov): how is it possible? why we don't stop the task in this case?
                } else {
                    //    stats
                    //        .total_packet_batches_sent
                    //        .fetch_add(1, Ordering::Relaxed);
                    //    stats
                    //        .total_packets_sent_to_consumer
                    //        .fetch_add(len, Ordering::Relaxed);
                    //    stats
                    //        .total_bytes_sent_to_consumer
                    //        .fetch_add(total_bytes, Ordering::Relaxed);
                    trace!("Sent {len} packet batch. total_bytes_sent_to_consumer: {total_bytes}");
                }
                break;
            }

            let timeout_res = if !packet_batch.is_empty() {
                // If we get here, elapsed < coalesce (see above if condition)
                timeout(coalesce - elapsed, packet_receiver.recv()).await
            } else {
                // Small bit of non-idealness here: the holder(s) of the other end
                // of packet_receiver must drop it (without waiting for us to exit)
                // or we have a chance of sleeping here forever
                // and never polling exit. Not a huge deal in practice as the
                // only time this happens is when we tear down the server
                // and at that time the other end does indeed not wait for us
                // to exit here
                Ok(packet_receiver.recv().await)
            };

            if let Ok(Ok(packet_accumulator)) = timeout_res {
                // Start the timeout from when the packet batch first becomes non-empty
                if packet_batch.is_empty() {
                    batch_start_time = Instant::now();
                }

                unsafe {
                    packet_batch.set_len(packet_batch.len() + 1);
                }

                let i = packet_batch.len() - 1;
                *packet_batch[i].meta_mut() = packet_accumulator.meta;
                let _num_chunks = packet_accumulator.chunks.len();
                for chunk in packet_accumulator.chunks {
                    packet_batch[i].buffer_mut()[chunk.offset..chunk.end_of_chunk]
                        .copy_from_slice(&chunk.bytes);
                }

                total_bytes += packet_batch[i].meta().size;

                if let Some(_signature) = signature_if_should_track_packet(&packet_batch[i])
                    .ok()
                    .flatten()
                {
                    //packet_perf_measure.push((*signature,
                    // packet_accumulator.start_time)); we set the
                    // PERF_TRACK_PACKET on set_track_performance is not
                    //implemented in 1.18 so just skip since we don't use these
                    //packets anyways
                    //packet_batch[i].meta_mut().set_track_performance(true);
                    // it should be `PERF_TRACK_PACKET` but it doesn't exist for 1.18.
                    // This packet is not used anyways, so set something to have a side effect to prevent this code to be optimized out.
                    packet_batch[i]
                        .meta_mut()
                        .flags
                        .set(PacketFlags::TRACER_PACKET, true);
                }
                //stats
                //    .total_chunks_processed_by_batcher
                //    .fetch_add(num_chunks, Ordering::Relaxed);
            }
        }
    }
}

// ShortVec is introduced in 2.0 so have to copy-paste it here

enum VisitStatus {
    Done(u16),
    More(u16),
}

#[derive(Debug)]
enum VisitError {
    TooLong(usize),
    //TooShort(usize),
    Overflow(u32),
    Alias,
    ByteThreeContinues,
}

type VisitResult = Result<VisitStatus, VisitError>;

const MAX_ENCODING_LENGTH: usize = 3;
fn visit_byte(elem: u8, val: u16, nth_byte: usize) -> VisitResult {
    if elem == 0 && nth_byte != 0 {
        return Err(VisitError::Alias);
    }

    let val = u32::from(val);
    let elem = u32::from(elem);
    let elem_val = elem & 0x7f;
    let elem_done = (elem & 0x80) == 0;

    if nth_byte >= MAX_ENCODING_LENGTH {
        return Err(VisitError::TooLong(nth_byte.saturating_add(1)));
    } else if nth_byte == MAX_ENCODING_LENGTH.saturating_sub(1) && !elem_done {
        return Err(VisitError::ByteThreeContinues);
    }

    let shift = u32::try_from(nth_byte)
        .unwrap_or(u32::MAX)
        .saturating_mul(7);
    let elem_val = elem_val.checked_shl(shift).unwrap_or(u32::MAX);

    let new_val = val | elem_val;
    let val = u16::try_from(new_val).map_err(|_| VisitError::Overflow(new_val))?;

    if elem_done {
        Ok(VisitStatus::Done(val))
    } else {
        Ok(VisitStatus::More(val))
    }
}

/// Return the decoded value and how many bytes it consumed.
#[allow(clippy::result_unit_err)]
pub fn decode_shortu16_len(bytes: &[u8]) -> Result<(usize, usize), ()> {
    let mut val = 0;
    for (nth_byte, byte) in bytes.iter().take(MAX_ENCODING_LENGTH).enumerate() {
        match visit_byte(*byte, val, nth_byte).map_err(|_| ())? {
            VisitStatus::More(new_val) => val = new_val,
            VisitStatus::Done(new_val) => {
                return Ok((usize::from(new_val), nth_byte.saturating_add(1)));
            }
        }
    }
    Err(())
}
