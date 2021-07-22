package sdk

// LiveUpload live streaming video upload manager
type LiveUpload struct {
	allocationObj *Allocation

	// delay  delay to upload video
	delay int

	liveMeta   LiveMeta
	liveReader LiveUploadReader

	// encryptOnUpload encrypt data on upload or not.
	encryptOnUpload bool
	// chunkSize how much bytes a chunk has. 64KB is default value.
	chunkSize int

	clipsIndex int

	// statusCallback trigger progress on StatusCallback
	statusCallback func() StatusCallback
}

// CreateLiveUpload create a LiveStreamUpload instance
func CreateLiveUpload(allocationObj *Allocation, liveMeta LiveMeta, liveReader LiveUploadReader, opts ...LiveUploadOption) *LiveUpload {
	u := &LiveUpload{
		allocationObj: allocationObj,
		//delay:         5 * time.Second,
		//clipsSize:    1024 * 1024 * 20, //50M
		liveMeta:   liveMeta,
		liveReader: liveReader,
		clipsIndex: 1,
	}

	for _, opt := range opts {
		opt(u)
	}

	return u
}

// Start start live streaming upload
func (lu *LiveUpload) Start() error {

	var err error
	var clipsUpload *StreamUpload
	for {

		clipsUpload = lu.createClipsUpload(lu.clipsIndex, lu.liveReader)

		err = clipsUpload.Start()

		if err != nil {
			return err
		}

		lu.clipsIndex++

	}

}

func (lu *LiveUpload) createClipsUpload(clipsIndex int, reader LiveUploadReader) *StreamUpload {
	fileMeta := FileMeta{
		Path:       reader.GetClipsFile(clipsIndex),
		ActualSize: reader.Size(),

		MimeType:   lu.liveMeta.MimeType,
		RemoteName: reader.GetClipsFileName(clipsIndex),
		RemotePath: lu.liveMeta.RemotePath + "/" + reader.GetClipsFileName(clipsIndex),
		Attributes: lu.liveMeta.Attributes,
	}

	return CreateStreamUpload(lu.allocationObj, fileMeta, reader,
		WithChunkSize(lu.chunkSize),
		WithEncrypt(lu.encryptOnUpload),
		WithStatusCallback(lu.statusCallback()))
}