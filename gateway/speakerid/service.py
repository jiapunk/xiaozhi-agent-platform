#!/usr/bin/env python3
"""Loopback-only, content-free speaker embedding service for the Gateway."""

from __future__ import annotations

import argparse
import base64
import json
import logging
import os
import subprocess
import threading
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import numpy as np
import sherpa_onnx


MAX_AUDIO_BYTES = 2 * 1024 * 1024
MIN_AUDIO_SAMPLES = 28_800  # 1.8 seconds at 16 kHz
MAX_AUDIO_SAMPLES = 16_000 * 46
MAX_FFMPEG_STDERR = 4096


class EmbeddingRuntime:
    def __init__(self, model: str, ffmpeg: str, threads: int) -> None:
        config = sherpa_onnx.SpeakerEmbeddingExtractorConfig(
            model=model,
            num_threads=threads,
            debug=False,
            provider="cpu",
        )
        if not config.validate():
            raise ValueError("speaker embedding model configuration is invalid")
        self.extractor = sherpa_onnx.SpeakerEmbeddingExtractor(config)
        self.ffmpeg = ffmpeg
        self.lock = threading.Lock()

    def embedding(self, encoded_audio: bytes) -> np.ndarray:
        process = subprocess.run(
            [
                self.ffmpeg,
                "-nostdin",
                "-hide_banner",
                "-loglevel",
                "error",
                "-i",
                "pipe:0",
                "-map",
                "0:a:0",
                "-ac",
                "1",
                "-ar",
                "16000",
                "-f",
                "f32le",
                "pipe:1",
            ],
            input=encoded_audio,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=8,
            check=False,
        )
        if process.returncode != 0 or len(process.stderr) > MAX_FFMPEG_STDERR:
            raise ValueError("audio decoding failed")
        samples = np.frombuffer(process.stdout, dtype="<f4")
        if not MIN_AUDIO_SAMPLES <= samples.size <= MAX_AUDIO_SAMPLES:
            raise ValueError("audio duration is outside the allowed range")
        if not np.all(np.isfinite(samples)):
            raise ValueError("audio contains non-finite samples")
        samples = np.ascontiguousarray(samples, dtype=np.float32)
        with self.lock:
            stream = self.extractor.create_stream()
            stream.accept_waveform(sample_rate=16_000, waveform=samples)
            stream.input_finished()
            if not self.extractor.is_ready(stream):
                raise ValueError("audio is insufficient for speaker embedding")
            vector = np.asarray(self.extractor.compute(stream), dtype=np.float32)
        norm = float(np.linalg.norm(vector))
        if vector.ndim != 1 or vector.size == 0 or vector.size > 1024 or norm < 1e-6:
            raise ValueError("speaker embedding is invalid")
        return np.ascontiguousarray(vector / norm, dtype="<f4")


class EmbeddingHandler(BaseHTTPRequestHandler):
    runtime: EmbeddingRuntime
    server_version = "XiaoZhiSpeakerID/1"
    sys_version = ""

    def log_message(self, format: str, *args: object) -> None:
        logging.info("speaker embedding request status=%s", args[1] if len(args) > 1 else "-")

    def do_GET(self) -> None:  # noqa: N802
        if self.path != "/healthz":
            self._json(HTTPStatus.NOT_FOUND, {"error": "not_found"})
            return
        self._json(HTTPStatus.OK, {"status": "ok"})

    def do_POST(self) -> None:  # noqa: N802
        if self.path != "/v1/embedding":
            self._json(HTTPStatus.NOT_FOUND, {"error": "not_found"})
            return
        if self.headers.get("Content-Type", "").split(";", 1)[0] != "audio/ogg":
            self._json(HTTPStatus.UNSUPPORTED_MEDIA_TYPE, {"error": "audio_ogg_required"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = 0
        if length <= 0 or length > MAX_AUDIO_BYTES:
            self._json(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, {"error": "invalid_audio_size"})
            return
        encoded_audio = self.rfile.read(length)
        if len(encoded_audio) != length:
            self._json(HTTPStatus.BAD_REQUEST, {"error": "incomplete_audio"})
            return
        try:
            vector = self.runtime.embedding(encoded_audio)
        except (ValueError, subprocess.TimeoutExpired):
            self._json(HTTPStatus.UNPROCESSABLE_ENTITY, {"error": "embedding_unavailable"})
            return
        payload = {
            "dimension": int(vector.size),
            "embedding": base64.b64encode(vector.tobytes()).decode("ascii"),
        }
        self._json(HTTPStatus.OK, payload)

    def _json(self, status: HTTPStatus, payload: dict[str, object]) -> None:
        data = json.dumps(payload, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
        self.send_response(status.value)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", default=os.environ.get("S3CAM_SPEAKER_MODEL", ""))
    parser.add_argument("--address", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8767)
    parser.add_argument("--threads", type=int, default=1)
    parser.add_argument("--ffmpeg", default="ffmpeg")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if not args.model or not os.path.isfile(args.model):
        raise SystemExit("speaker model file is required")
    if args.address not in ("127.0.0.1", "::1"):
        raise SystemExit("speaker embedding service must bind to loopback")
    if args.threads != 1:
        raise SystemExit("this VPS profile requires exactly one inference thread")
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    EmbeddingHandler.runtime = EmbeddingRuntime(args.model, args.ffmpeg, args.threads)
    server = ThreadingHTTPServer((args.address, args.port), EmbeddingHandler)
    logging.info("speaker embedding service ready address=%s port=%d", args.address, args.port)
    server.serve_forever()


if __name__ == "__main__":
    main()
