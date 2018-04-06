from PacketHandler.Filters.tcp_regex_filter import TcpRegexFilter


class CookieFilter(TcpRegexFilter):

    def __init__(self):
        super(CookieFilter, self).__init__('^((?<!\r\n\r\n)[\s\S]*?((Set-)?Cookie: .+))', 2)
