package sdk

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"math"
	"os"
	"sync"

	"github.com/0chain/errors"

	"github.com/0chain/gosdk/core/sys"
	"github.com/0chain/gosdk/zboxcore/blockchain"
	"github.com/0chain/gosdk/zboxcore/client"
	"github.com/0chain/gosdk/zboxcore/encoder"
	"github.com/0chain/gosdk/zboxcore/encryption"
	"github.com/0chain/gosdk/zboxcore/fileref"
	"github.com/0chain/gosdk/zboxcore/logger"
	"github.com/0chain/gosdk/zboxcore/marker"
	"github.com/0chain/gosdk/zboxcore/zboxutil"
	"go.dedis.ch/kyber/v3/group/edwards25519"
)

const (
	DOWNLOAD_CONTENT_FULL  = "full"
	DOWNLOAD_CONTENT_THUMB = "thumbnail"
)

type DownloadRequest struct {
	allocationID       string
	allocationTx       string
	allocOwnerID       string
	blobbers           []*blockchain.StorageNode
	datashards         int
	parityshards       int
	remotefilepath     string
	remotefilepathhash string
	localpath          string
	startBlock         int64
	endBlock           int64
	chunkSize          int
	numBlocks          int64
	rxPay              bool
	statusCallback     StatusCallback
	ctx                context.Context
	ctxCncl            context.CancelFunc
	authTicket         *marker.AuthTicket
	wg                 *sync.WaitGroup
	downloadMask       zboxutil.Uint128
	encryptedKey       string
	isDownloadCanceled bool
	completedCallback  func(remotepath string, remotepathhash string)
	contentMode        string
	Consensus
}

func (req *DownloadRequest) downloadBlock(blockNum int64, blockChunksMax int) ([]byte, error) {
	req.consensus = 0
	numDownloads := req.downloadMask.CountOnes()
	req.wg = &sync.WaitGroup{}
	req.wg.Add(numDownloads)
	rspCh := make(chan *downloadBlock, numDownloads)

	var c, pos int
	for i := req.downloadMask; !i.Equals64(0); i = i.And(zboxutil.NewUint128(1).Lsh(uint64(pos)).Not()) {
		pos = i.TrailingZeros()
		blockDownloadReq := &BlockDownloadRequest{
			allocationID:       req.allocationID,
			allocationTx:       req.allocationTx,
			allocOwnerID:       req.allocOwnerID,
			authTicket:         req.authTicket,
			blobber:            req.blobbers[pos],
			blobberIdx:         pos,
			chunkSize:          req.chunkSize,
			blockNum:           blockNum,
			contentMode:        req.contentMode,
			result:             rspCh,
			wg:                 req.wg,
			ctx:                req.ctx,
			remotefilepath:     req.remotefilepath,
			remotefilepathhash: req.remotefilepathhash,
			numBlocks:          req.numBlocks,
			rxPay:              req.rxPay,
			encryptedKey:       req.encryptedKey,
		}
		go AddBlockDownloadReq(blockDownloadReq)
		c++
	}

	shards := make([][][]byte, req.numBlocks)
	for i := int64(0); i < req.numBlocks; i++ {
		shards[i] = make([][]byte, len(req.blobbers))
	}

	decodeLen := make([]int, req.numBlocks)
	var decodeNumBlocks int

	retData := make([]byte, 0)
	success := 0
	logger.Logger.Info("downloadBlock ", blockNum, " numDownloads ", numDownloads)

	var encscheme encryption.EncryptionScheme
	if len(req.encryptedKey) > 0 {
		encscheme = encryption.NewEncryptionScheme()
		encscheme.Initialize(client.GetClient().Mnemonic)
		encscheme.InitForDecryption("filetype:audio", req.encryptedKey)
	}

	for i := 0; i < numDownloads; i++ {
		result := <-rspCh

		downloadChunks := len(result.BlockChunks)
		if !result.Success {
			logger.Logger.Error("Download block : ", req.blobbers[result.idx].Baseurl, " ", result.err)
			return nil, result.err
		}

		blockSuccess := false
		if blockChunksMax < len(result.BlockChunks) {
			downloadChunks = blockChunksMax
		}

		for blockNum := 0; blockNum < downloadChunks; blockNum++ {
			var data []byte
			var err error
			if len(req.encryptedKey) > 0 {
				if req.authTicket == nil {
					data, err = decryptForOwner(result, encscheme, blockNum)
				} else {
					data, err = decryptForAuthTicket(result, encscheme, blockNum)
				}

				if err != nil {
					logger.Logger.Error(err)
					break
				}
			} else {
				data = result.BlockChunks[blockNum]
			}

			shards[blockNum][result.idx] = data

			// All share should have equal length
			decodeLen[blockNum] = len(shards[blockNum][result.idx])
			blockSuccess = true
		}

		if !blockSuccess {
			continue
		}

		success++
		if success >= req.datashards {
			decodeNumBlocks = downloadChunks
			break
		}
	}

	erasureencoder, err := encoder.NewEncoder(req.datashards, req.parityshards)
	if err != nil {
		return nil, errors.Wrap(err, "encoder init error")
	}
	for blockNum := 0; blockNum < decodeNumBlocks; blockNum++ {
		data, err := erasureencoder.Decode(shards[blockNum], decodeLen[blockNum])
		if err != nil {
			return nil, errors.Wrap(err, "Block decode error")
		}
		retData = append(retData, data...)
	}
	return retData, nil
}

func (req *DownloadRequest) processDownload(ctx context.Context) {
	defer req.ctxCncl()
	remotePathCallback := req.remotefilepath
	if len(req.remotefilepath) == 0 {
		remotePathCallback = req.remotefilepathhash
	}
	if req.completedCallback != nil {
		defer req.completedCallback(req.remotefilepath, req.remotefilepathhash)
	}

	// Only download from the Blobbers passes the consensus
	var fileRef *fileref.FileRef
	listReq := &ListRequest{
		remotefilepath:     req.remotefilepath,
		remotefilepathhash: req.remotefilepathhash,
		allocationID:       req.allocationID,
		allocationTx:       req.allocationTx,
		blobbers:           req.blobbers,
		ctx:                req.ctx,
		authToken:          req.authTicket,
		Consensus: Consensus{
			fullconsensus:          req.fullconsensus,
			consensusThresh:        req.consensusThresh,
			consensusRequiredForOk: req.consensusRequiredForOk,
		},
	}
	req.downloadMask, fileRef, _ = listReq.getFileConsensusFromBlobbers()
	if req.downloadMask.Equals64(0) || fileRef == nil {
		if req.statusCallback != nil {
			req.statusCallback.Error(req.allocationID, remotePathCallback, OpDownload, errors.New("", "No minimum consensus for file meta data of file"))
		}
		return
	}

	if fileRef.Type == fileref.DIRECTORY {
		if req.statusCallback != nil {
			req.statusCallback.Error(req.allocationID, remotePathCallback, OpDownload, errors.New("", "please get files from folder, and download them one by one"))
		}
		return
	}

	size := fileRef.ActualFileSize
	if req.contentMode == DOWNLOAD_CONTENT_THUMB {
		size = fileRef.ActualThumbnailSize
	}
	req.encryptedKey = fileRef.EncryptedKey
	req.chunkSize = int(fileRef.ChunkSize)
	logger.Logger.Info("Encrypted key from fileref", req.encryptedKey)

	perShard := int64(math.Ceil(float64(size) / float64(req.datashards)))
	effectiveChunkSize := int64(fileRef.ChunkSize)
	if len(fileRef.EncryptedKey) > 0 {
		effectiveChunkSize -= (EncryptedDataPaddingSize + EncryptionHeaderSize)
	}

	chunksPerShard := int64(math.Ceil(float64(perShard) / float64(effectiveChunkSize)))

	wrFile, err := sys.Files.OpenFile(req.localpath, os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		if req.statusCallback != nil {
			logger.Logger.Error(err.Error())
			req.statusCallback.Error(req.allocationID, remotePathCallback, OpDownload, errors.Wrap(err, "Can't create local file"))
		}
		return
	}
	defer wrFile.Close()
	req.isDownloadCanceled = false
	if req.statusCallback != nil {
		req.statusCallback.Started(req.allocationID, remotePathCallback, OpDownload, int(size))
	}

	if req.endBlock == 0 {
		req.endBlock = chunksPerShard
	}

	if req.startBlock >= req.endBlock {
		if req.statusCallback != nil {
			sys.Files.Remove(req.localpath)
			req.statusCallback.Error(req.allocationID, remotePathCallback, OpDownload, errors.New("invalid_block_num", "start block should be less than end block"))
		}
		return
	}

	logger.Logger.Info("Start block: ", req.startBlock+1, " End block: ", req.endBlock, " Num blocks: ", req.numBlocks)

	downloaded := int(0)
	fileHasher := createDownloadHasher(req.chunkSize, req.datashards, len(fileRef.EncryptedKey) > 0)
	mW := io.MultiWriter(fileHasher, wrFile)

	startBlock := req.startBlock
	endBlock := req.endBlock
	numBlocks := req.numBlocks
	wantSize := (endBlock - startBlock) * effectiveChunkSize
	if endBlock >= chunksPerShard {
		fragmentSize := int64(req.chunkSize) * int64(req.datashards)
		resultantFileSize := fragmentSize * int64(chunksPerShard)
		padding := resultantFileSize - size
		wantSize -= padding
	}

	for startBlock < endBlock {
		cnt := startBlock
		logger.Logger.Info("Downloading block ", cnt+1)
		if (startBlock + numBlocks) > endBlock {
			numBlocks = endBlock - startBlock
		}

		data, err := req.downloadBlock(cnt+1, int(numBlocks))
		if err != nil {
			sys.Files.Remove(req.localpath)
			if req.statusCallback != nil {
				req.statusCallback.Error(req.allocationID, remotePathCallback, OpDownload, errors.Wrap(err, fmt.Sprintf("Download failed for block %d. ", cnt+1)))
			}
			return
		}
		if req.isDownloadCanceled {
			req.isDownloadCanceled = false
			sys.Files.Remove(req.localpath)
			if req.statusCallback != nil {
				req.statusCallback.Error(req.allocationID, remotePathCallback, OpDownload, errors.New("", "Download aborted by user"))
			}
			return
		}

		n := int64(math.Min(float64(wantSize), float64(len(data))))
		_, err = mW.Write(data[:n])

		if err != nil {
			sys.Files.Remove(req.localpath) //nolint: errcheck
			if req.statusCallback != nil {
				req.statusCallback.Error(req.allocationID, remotePathCallback, OpDownload, errors.Wrap(err, "Write file failed"))
			}
			return
		}
		downloaded = downloaded + int(n)
		wantSize = wantSize - n

		if req.statusCallback != nil {
			req.statusCallback.InProgress(req.allocationID, remotePathCallback, OpDownload, downloaded, data)
		}

		if (startBlock + numBlocks) > endBlock {
			startBlock += endBlock - startBlock
		} else {
			startBlock += numBlocks
		}
	}

	// Only check hash when the download request is not by block/partial.
	if req.endBlock == chunksPerShard && req.startBlock == 0 {
		//calcHash := fileHasher.GetHash()
		merkleRoot := fileHasher.GetMerkleRoot()

		expectedHash := fileRef.ActualFileHash
		if req.contentMode == DOWNLOAD_CONTENT_THUMB {
			expectedHash = fileRef.ActualThumbnailHash
		}

		//if calcHash != expectedHash && expectedHash != merkleRoot {
		if expectedHash != merkleRoot {
			sys.Files.Remove(req.localpath) //nolint: errcheck
			if req.statusCallback != nil {
				req.statusCallback.Error(req.allocationID, remotePathCallback, OpDownload, errors.New("", "File content didn't match with uploaded file"))
			}
			return
		}
	}

	wrFile.Sync()
	wrFile.Close()
	wrFile, _ = sys.Files.Open(req.localpath)
	defer wrFile.Close()
	wrFile.Seek(0, 0)
	mimetype, _ := zboxutil.GetFileContentType(wrFile)
	if req.statusCallback != nil {
		req.statusCallback.Completed(req.allocationID, remotePathCallback, fileRef.Name, mimetype, int(fileRef.ActualFileSize), OpDownload)
	}
}

func decryptForOwner(result *downloadBlock, encScheme encryption.EncryptionScheme, blockNum int) ([]byte, error) {
	headerBytes := result.BlockChunks[blockNum][:EncryptionHeaderSize]
	headerBytes = bytes.Trim(headerBytes, "\x00")

	if len(headerBytes) != EncryptionHeaderSize {
		return nil, errors.New("invalid_block_header", "")
	}

	encMsg := &encryption.EncryptedMessage{}
	encMsg.EncryptedData = result.BlockChunks[blockNum][EncryptionHeaderSize:]

	encMsg.MessageChecksum, encMsg.OverallChecksum = string(headerBytes[:128]), string(headerBytes[128:])
	encMsg.EncryptedKey = encScheme.GetEncryptedKey()
	decrypted, err := encScheme.Decrypt(encMsg)
	if err != nil {
		return nil, errors.New("decryption_error", err.Error())
	}
	return decrypted, nil
}

func decryptForAuthTicket(result *downloadBlock, encScheme encryption.EncryptionScheme, blockNum int) ([]byte, error) {
	suite := edwards25519.NewBlakeSHA256Ed25519()
	reEncMessage := &encryption.ReEncryptedMessage{
		D1: suite.Point(),
		D4: suite.Point(),
		D5: suite.Point(),
	}
	err := reEncMessage.Unmarshal(result.BlockChunks[blockNum])
	if err != nil {
		return nil, errors.New("unmarshal_error", err.Error())
	}

	decrypted, err := encScheme.ReDecrypt(reEncMessage)
	if err != nil {
		return nil, errors.New("redecryption_error", err.Error())
	}

	return decrypted, nil
}
