"""示例脚本：复用 IDS passkey 登录态访问研究生选课系统。"""

import argparse
import logging
import time

import urllib3

from shanghaitech_ids_passkey import IDSClient, PasskeyKeystore


urllib3.disable_warnings()

LOGGER = logging.getLogger(__name__)

COURSE_CHOOSE_URL = (
    "https://10.15.144.85/yjsxkapp/sys/xsxkapp/xsxkCourse/choiceCourse.do?_={0}"
)
CSRF_URL = "https://10.15.144.85/yjsxkapp/sys/xsxkapp/xsxkHome/loadPublicInfo_course.do"
COURSE_SERVICE_URL = (
    "https://ids.shanghaitech.edu.cn/authserver/login"
    "?service=https%3A%2F%2Fgraduate-course.shanghaitech.edu.cn"
    "%2Fyjsxkapp%2Fsys%2Fxsxkapp%2F*default%2Findex.do"
)


class CourseChooser:
    """仅作示例：展示如何复用 IDS 登录 cookies。"""

    def __init__(self, client: IDSClient) -> None:
        self.client = client
        self.headers = {
            "accept": "application/json, text/javascript, */*; q=0.01",
            "cache-control": "no-cache",
            "content-type": "application/x-www-form-urlencoded; charset=UTF-8",
            "pragma": "no-cache",
            "referer": "https://graduate-course.shanghaitech.edu.cn/yjsxkapp/sys/xsxkapp/course.html",
            "x-requested-with": "XMLHttpRequest",
        }

    def bootstrap(self) -> None:
        self.client.get_service(COURSE_SERVICE_URL, allow_redirects=True, verify=False)

    def fetch_csrf_token(self) -> str:
        self.bootstrap()
        response = self.client.session.get(
            CSRF_URL,
            headers=self.headers,
            verify=False,
            timeout=self.client.config.timeout,
        )
        response.raise_for_status()
        data = response.json()
        return data.get("csrfToken", "")

    def choose_course(self, course_id: str) -> dict:
        csrf_token = self.fetch_csrf_token()
        response = self.client.session.post(
            COURSE_CHOOSE_URL.format(int(time.time() * 1000)),
            headers=self.headers,
            data={"csrfToken": csrf_token, "bjdm": course_id, "lx": 0},
            verify=False,
            timeout=self.client.config.timeout,
        )
        response.raise_for_status()
        return response.json()


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    parser = argparse.ArgumentParser()
    parser.add_argument("--keystore", required=True, help="passkey keystore 文件路径。")
    parser.add_argument("course_ids", nargs="+", help="要尝试的课程编号。")
    args = parser.parse_args()

    keystore = PasskeyKeystore.load(args.keystore)
    client = IDSClient(keystore)
    chooser = CourseChooser(client)

    try:
        while args.course_ids:
            for course_id in list(args.course_ids):
                result = chooser.choose_course(course_id)
                LOGGER.info("%s -> %s", course_id, result)
                if result.get("msg") == "选择的教学班不在您的可选范围内 (#uu1ud)":
                    args.course_ids.remove(course_id)
            time.sleep(0.1)
    finally:
        keystore.dump(args.keystore)
        client.logout()


if __name__ == "__main__":
    main()
