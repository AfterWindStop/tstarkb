# coding=utf-8
"""
    @project: maxkb
    @Author：虎
    @file： image_serializers.py
    @date：2024/4/22 16:36
    @desc:
"""
import uuid

from django.db.models import QuerySet
from django.http import HttpResponse
from rest_framework import serializers

from common.exception.app_exception import NotFound404
from common.field.common import UploadedFileField
from common.util.field_message import ErrMessage
from dataset.models import File
from django.utils.translation import gettext_lazy as _
from dataset.serializers.eml2docx import process_eml_files
import os 

mime_types = {"html": "text/html", "htm": "text/html", "shtml": "text/html", "css": "text/css", "xml": "text/xml",
              "gif": "image/gif", "jpeg": "image/jpeg", "jpg": "image/jpeg", "js": "application/javascript",
              "atom": "application/atom+xml", "rss": "application/rss+xml", "mml": "text/mathml", "txt": "text/plain",
              "jad": "text/vnd.sun.j2me.app-descriptor", "wml": "text/vnd.wap.wml", "htc": "text/x-component",
              "avif": "image/avif", "png": "image/png", "svg": "image/svg+xml", "svgz": "image/svg+xml",
              "tif": "image/tiff", "tiff": "image/tiff", "wbmp": "image/vnd.wap.wbmp", "webp": "image/webp",
              "ico": "image/x-icon", "jng": "image/x-jng", "bmp": "image/x-ms-bmp", "woff": "font/woff",
              "woff2": "font/woff2", "jar": "application/java-archive", "war": "application/java-archive",
              "ear": "application/java-archive", "json": "application/json", "hqx": "application/mac-binhex40",
              "doc": "application/msword", "pdf": "application/pdf", "ps": "application/postscript",
              "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
              "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
              "pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
              "eps": "application/postscript", "ai": "application/postscript", "rtf": "application/rtf",
              "m3u8": "application/vnd.apple.mpegurl", "kml": "application/vnd.google-earth.kml+xml",
              "kmz": "application/vnd.google-earth.kmz", "xls": "application/vnd.ms-excel",
              "eot": "application/vnd.ms-fontobject", "ppt": "application/vnd.ms-powerpoint",
              "odg": "application/vnd.oasis.opendocument.graphics",
              "odp": "application/vnd.oasis.opendocument.presentation",
              "ods": "application/vnd.oasis.opendocument.spreadsheet", "odt": "application/vnd.oasis.opendocument.text",
              "wmlc": "application/vnd.wap.wmlc", "wasm": "application/wasm", "7z": "application/x-7z-compressed",
              "cco": "application/x-cocoa", "jardiff": "application/x-java-archive-diff",
              "jnlp": "application/x-java-jnlp-file", "run": "application/x-makeself", "pl": "application/x-perl",
              "pm": "application/x-perl", "prc": "application/x-pilot", "pdb": "application/x-pilot",
              "rar": "application/x-rar-compressed", "rpm": "application/x-redhat-package-manager",
              "sea": "application/x-sea", "swf": "application/x-shockwave-flash", "sit": "application/x-stuffit",
              "tcl": "application/x-tcl", "tk": "application/x-tcl", "der": "application/x-x509-ca-cert",
              "pem": "application/x-x509-ca-cert", "crt": "application/x-x509-ca-cert",
              "xpi": "application/x-xpinstall", "xhtml": "application/xhtml+xml", "xspf": "application/xspf+xml",
              "zip": "application/zip", "bin": "application/octet-stream", "exe": "application/octet-stream",
              "dll": "application/octet-stream", "deb": "application/octet-stream", "dmg": "application/octet-stream",
              "iso": "application/octet-stream", "img": "application/octet-stream", "msi": "application/octet-stream",
              "msp": "application/octet-stream", "msm": "application/octet-stream", "mid": "audio/midi",
              "midi": "audio/midi", "kar": "audio/midi", "mp3": "audio/mpeg", "ogg": "audio/ogg", "m4a": "audio/x-m4a",
              "ra": "audio/x-realaudio", "3gpp": "video/3gpp", "3gp": "video/3gpp", "ts": "video/mp2t",
              "mp4": "video/mp4", "mpeg": "video/mpeg", "mpg": "video/mpeg", "mov": "video/quicktime",
              "webm": "video/webm", "flv": "video/x-flv", "m4v": "video/x-m4v", "mng": "video/x-mng",
              "asx": "video/x-ms-asf", "asf": "video/x-ms-asf", "wmv": "video/x-ms-wmv", "avi": "video/x-msvideo"}


class FileSerializer(serializers.Serializer):
    file = UploadedFileField(required=True, error_messages=ErrMessage.image(_('file')))
    meta = serializers.JSONField(required=False, allow_null=True)
    need_change = serializers.BooleanField(required=False, default=False)

    def upload(self, with_valid=True):
        if with_valid:
            self.is_valid(raise_exception=True)
        meta = self.data.get('meta', None)
        if not meta:
            meta = {'debug': True}
        original_file = self.data.get('file')
        file_name = ''
        local_path = ''
        import tempfile
        # 执行转换
        original_name = original_file.name
        if self.validated_data.get('need_change') is True:
            # 执行eml文件转换成docx格式
            try:
                base_name = os.path.splitext(original_name)[0]  # 获取不带扩展名的文件名
                with tempfile.TemporaryDirectory() as temp_dir:
                    eml_file_path = os.path.join(temp_dir, original_name)  # 在临时目录中创建eml文件路径
                    with open(eml_file_path, 'wb') as temp_eml_file:
                        temp_eml_file.write(original_file.read())  # 将内存中的文件写入临时文件
                    docx_file_path = os.path.join(temp_dir, f"{base_name}.docx")  # 生成docx文件路径
                    from pathlib import Path
                    process_eml_files(Path(eml_file_path))  # 调用转换函数
                    file_id = meta.get('file_id', uuid.uuid1())
                    file = File(id=file_id, file_name=os.path.basename(docx_file_path), meta=meta)
                    file_name = os.path.basename(docx_file_path)
                    # file = File(id=file_id, file_name=self.data.get('file').name, meta=meta)
                    # file_name = self.data.get('file').name
                    file.save(open(docx_file_path, 'rb').read())
                local_path = eml_file_path
            except Exception as e:
                local_path = ''
        else:
            file_id = meta.get('file_id', uuid.uuid1())
            file = File(id=file_id, file_name=self.data.get('file').name, meta=meta)
            file_name = self.data.get('file').name
            file_bytes = self.data.get('file').read()
            file.save(file_bytes)
            try:
                local_path = f"/tmp/{file_name}"
                with open(local_path, 'wb') as f:
                    f.write(file_bytes)
            except Exception as e:
                local_path = ''
        return f'/api/file/{file_id}', file_name, local_path


    class Operate(serializers.Serializer):
        id = serializers.UUIDField(required=True)

        def get(self, with_valid=True):
            if with_valid:
                self.is_valid(raise_exception=True)
            file_id = self.data.get('id')
            file = QuerySet(File).filter(id=file_id).first()
            if file is None:
                raise NotFound404(404, _('File not found'))
            # 如果是音频文件，直接返回文件流
            file_type = file.file_name.split(".")[-1]
            if file_type in ['mp3', 'wav', 'ogg', 'aac']:
                return HttpResponse(file.get_byte(), status=200, headers={'Content-Type': f'audio/{file_type}',
                                                                          'Content-Disposition': 'attachment; filename="{}"'.format(
                                                                              file.file_name)})
            return HttpResponse(file.get_byte(), status=200,
                                headers={'Content-Type': mime_types.get(file_type, 'text/plain')})
