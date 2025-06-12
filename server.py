from flask import Flask, request, send_from_directory, jsonify
import os
import logging
import sys

app = Flask(__name__)

# 设置资源文件夹路径
RESOURCE_FOLDER = "Resource"

# 确保资源文件夹存在
if not os.path.exists(RESOURCE_FOLDER):
    os.makedirs(RESOURCE_FOLDER)


@app.route("/download/<path:filename>", methods=["GET"])
def download_file(filename):
    """
    提供文件下载接口
    客户端可以通过 http://<server_address>/download/<filename> 来下载文件
    """
    try:
        # 检查文件是否存在
        file_path = os.path.join(RESOURCE_FOLDER, filename)
        if os.path.exists(file_path):
            return send_from_directory(RESOURCE_FOLDER, filename, as_attachment=True)
        else:
            return jsonify({"error": "File not found"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/upload", methods=["POST"])
def upload_data():
    """
    提供数据上传接口
    客户端可以通过 POST 请求向服务器发送数据
    """
    try:
        # 获取请求中的原始数据
        data = request.data.decode("utf-8")  # 获取原始请求体并解码为字符串
        if data:
            # 处理数据（这里只是简单打印数据）
            with open("./file_moede_res", "w") as fd:
                fd.write(data)
            return jsonify({"message": "Data received successfully"}), 200
        else:
            return jsonify({"error": "No data received"}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    # no debug info
    sys.stdout = open('NUL', 'w')
    sys.stderr = open('NUL', 'w')

    app.run(host="0.0.0.0", port=8048, debug=False)


