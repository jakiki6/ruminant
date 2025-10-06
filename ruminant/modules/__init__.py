from .. import module
from ..buf import Buf

import traceback
import os

to_extract = []
extract_all = False
blob_id = 0


class EntryModule(module.RuminantModule):

    def __init__(self, walk_mode, blob_mode, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.walk_mode = walk_mode
        self.blob_mode = blob_mode

    def chew(self):
        global blob_id

        meta = {}
        meta["blob-id"] = blob_id
        my_blob_id = blob_id
        blob_id += 1

        offset = self.buf.tell()

        matched = False

        if self.blob_mode:
            matched = True
            meta["type"] = "blob"
            meta["length"] = self.buf.size()
            self.buf.skip(self.buf.size())
        else:
            for m in module.modules:
                if m.identify(self.buf, {"walk": self.walk_mode}):
                    try:
                        rest = m(self.buf).chew()
                    except Exception as e:
                        if self.walk_mode:
                            raise e

                        self.buf.skip(self.buf.available())

                        stack_list = []
                        for frame in traceback.extract_tb(e.__traceback__):
                            stack_list.append({
                                "filename": frame.filename,
                                "lineno": frame.lineno,
                                "name": frame.name,
                                "line": frame.line
                            })

                        rest = {
                            "type": "error",
                            "module": m.__name__,
                            "error-type": type(e).__name__,
                            "error-message": str(e),
                            "stack": stack_list
                        }

                    meta["length"] = self.buf.tell()
                    meta |= rest

                    matched = True

                    if self.buf.available() and not self.walk_mode:
                        with self.buf.cut():
                            meta = {"type": "nested", "segments": [meta]}

                            trailer = self.chew()
                            if trailer["type"] == "nested":
                                meta["segments"] += trailer["segments"]
                            else:
                                meta["segments"].append(trailer)

                        self.buf.skip(self.buf.available())
                    break

        if not matched:
            meta |= {"type": "unknown", "length": self.buf.size()}

        if extract_all and my_blob_id > 0:
            to_extract.append(
                (my_blob_id,
                 os.path.join("blobs", f"{str(my_blob_id).zfill(8)}.bin")))

        for entry in to_extract[:]:
            k, v = entry

            if k == my_blob_id:
                to_extract.remove(entry)

                with self.buf:
                    self.buf.resetunit()
                    self.buf.seek(offset)

                    with open(v, "wb") as file:
                        length = meta["length"] if meta[
                            "type"] != "nested" else meta["segments"][0][
                                "length"]

                        while length:
                            blob = self.buf.read(min(1 << 24, length))
                            file.write(blob)
                            length -= len(blob)

                            if len(blob) == 0:
                                break

        return meta


def chew(blob, walk_mode=False, blob_mode=False):
    return EntryModule(walk_mode, blob_mode, Buf.of(blob)).chew()


from . import containers, images, videos, documents, fonts, audio, crypto, compression, text, misc  # noqa: F401,E402
