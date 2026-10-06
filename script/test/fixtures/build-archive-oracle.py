#!/usr/bin/env python3
"""Independent buildx stdout shape/integrity oracle; reads without extracting."""
import io
import tempfile
import copy
import hashlib
import json
import platform
import sys
import tarfile

INDEX = {"application/vnd.oci.image.index.v1+json", "application/vnd.docker.distribution.manifest.list.v2+json"}
MANIFEST = {"application/vnd.oci.image.manifest.v1+json", "application/vnd.docker.distribution.manifest.v2+json"}


def inspect(path):
    if not __debug__:
        raise RuntimeError("archive oracle requires assertions enabled")
    host = {"aarch64": "arm64", "arm64": "arm64", "x86_64": "amd64"}[platform.machine()]
    with tarfile.open(path) as archive:
        members = archive.getmembers()
        assert len(members) < 100000, "member bound"
        names = [m.name.removeprefix("./") for m in members]
        assert len(names) == len(set(names)), "duplicate archive members"
        table = dict(zip(names, members))

        def read(name):
            member = table[name]
            assert member.isfile(), "nonregular blob"
            return archive.extractfile(member).read()

        def blob(desc):
            algorithm, digest = desc["digest"].split(":", 1)
            assert algorithm == "sha256", "unknown digest"
            data = read("blobs/sha256/" + digest)
            assert len(data) == desc["size"], "size mismatch"
            assert hashlib.sha256(data).hexdigest() == digest, "digest mismatch"
            return data

        def clean(node):
            assert "subject" not in node and "artifactType" not in node, "artifact"
            annotations = node.get("annotations", {})
            assert "org.opencontainers.image.ref.name" not in annotations, "result alias"
            assert not any("attestation" in k or "attestation" in str(v) for k, v in annotations.items()), "attestation"

        leaves = []
        visited = 0

        def walk(desc, ancestors):
            nonlocal visited
            visited += 1
            assert visited <= 128 and len(ancestors) < 16, "descriptor bounds"
            clean(desc)
            digest = desc["digest"]
            assert digest not in ancestors, "descriptor cycle"
            declared = desc.get("platform")
            if declared:
                assert declared["os"] == "linux" and declared["architecture"] == host, "foreign platform"
            node = json.loads(blob(desc))
            clean(node)
            media = desc["mediaType"]
            if media in INDEX:
                for child in node["manifests"]:
                    walk(child, ancestors + [digest])
            else:
                assert media in MANIFEST, "unknown descriptor media type"
                assert declared, "leaf must declare platform"
                clean(node["config"])
                assert node["config"]["mediaType"] in {"application/vnd.oci.image.config.v1+json", "application/vnd.docker.container.image.v1+json"}, "unknown config media type"
                config = json.loads(blob(node["config"]))
                assert config["os"] == "linux" and config["architecture"] == host, "foreign config"
                for layer in node["layers"]:
                    clean(layer)
                    assert layer["mediaType"] in {"application/vnd.oci.image.layer.v1.tar", "application/vnd.oci.image.layer.v1.tar+gzip", "application/vnd.oci.image.layer.v1.tar+zstd", "application/vnd.docker.image.rootfs.diff.tar.gzip"}, "unknown layer media type"
                    blob(layer)
                leaves.append(digest)

        index = json.loads(read("index.json"))
        clean(index)
        for desc in index["manifests"]:
            walk(desc, [])
        assert len(leaves) == 1, "must export exactly one runnable image"
        return {"platform": "linux/" + host, "manifests": leaves, "descriptors": visited}


def controls(path):
    inspect(path)
    with tarfile.open(path) as source:
        entries = [(m, source.extractfile(m).read() if m.isfile() else None) for m in source.getmembers()]
    for mutation in ["alias", "extra-foreign", "extra-attestation"]:
        with tempfile.NamedTemporaryFile(suffix=".tar") as altered:
            with tarfile.open(altered.name, "w") as dest:
                for member, data in entries:
                    member = copy.copy(member)
                    if member.name.removeprefix("./") == "index.json":
                        index = json.loads(data)
                        if mutation == "alias":
                            index["manifests"][0].setdefault("annotations", {})["org.opencontainers.image.ref.name"] = "alias:dev"
                        else:
                            extra = copy.deepcopy(index["manifests"][0])
                            if mutation == "extra-foreign":
                                extra["platform"] = {"os": "linux", "architecture": "foreign"}
                            else:
                                extra.setdefault("annotations", {})["vnd.docker.reference.type"] = "attestation-manifest"
                            index["manifests"].append(extra)
                        data = json.dumps(index).encode()
                        member.size = len(data)
                    dest.addfile(member, io.BytesIO(data) if data is not None else None)
            try:
                inspect(altered.name)
            except AssertionError:
                continue
            raise AssertionError("oracle accepted " + mutation)
    print("archive oracle negative controls passed")


if __name__ == "__main__":
    if sys.argv[1] == "--controls":
        controls(sys.argv[2])
    else:
        print(json.dumps(inspect(sys.argv[1]), sort_keys=True))
