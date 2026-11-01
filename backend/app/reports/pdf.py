"""Build complete, printable PDF reports from saved scan evidence."""

from __future__ import annotations

from datetime import UTC, datetime
from io import BytesIO
from pathlib import Path
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.lib.utils import ImageReader, simpleSplit
from reportlab.platypus import (
    BaseDocTemplate,
    Flowable,
    Frame,
    LongTable,
    PageBreak,
    PageTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)

from app.models import ScanJob, WorkspaceSettings

INK = colors.HexColor("#14231f")
MUTED = colors.HexColor("#52645e")
EMERALD = colors.HexColor("#087f5b")
LOGO_PATH = Path(__file__).with_name("najd-recon-logo.png")
PALETTE = {
    "critical": colors.HexColor("#b42318"),
    "high": colors.HexColor("#dc6803"),
    "medium": colors.HexColor("#b58105"),
    "low": colors.HexColor("#087f5b"),
    "none": colors.HexColor("#64748b"),
    "unknown": colors.HexColor("#94a3b8"),
    "open": colors.HexColor("#087f5b"),
    "closed": colors.HexColor("#64748b"),
    "filtered": colors.HexColor("#b58105"),
}


def _plain(value: object) -> str:
    return (
        str(value if value is not None else "Not available")
        .encode("latin-1", "replace")
        .decode("latin-1")
    )


def _paragraph(value: object, style: ParagraphStyle) -> Paragraph:
    text = escape(_plain(value)).replace("\n", "<br/>")
    return Paragraph(text, style)


class ObservationMap(Flowable):
    """Illustrate scan scope, observed hosts and services without implying traffic paths."""

    def __init__(self, target: str, hosts: list):
        super().__init__()
        self.target = _plain(target)
        self.hosts = hosts
        self.width = 0
        self.height = 54 + min(len(hosts), 12) * 47

    def wrap(self, available_width: float, available_height: float) -> tuple[float, float]:
        self.width = available_width
        return self.width, self.height

    def draw(self) -> None:
        canvas = self.canv
        canvas.saveState()
        canvas.setStrokeColor(colors.HexColor("#9bb9ad"))
        canvas.setFillColor(colors.HexColor("#eaf5ef"))
        root_x = self.width / 2
        canvas.roundRect(root_x - 105, self.height - 36, 210, 26, 6, fill=1, stroke=1)
        canvas.setFillColor(INK)
        canvas.setFont("Times-Bold", 12)
        canvas.drawCentredString(root_x, self.height - 26, f"Scanned scope: {self.target[:34]}")

        shown = self.hosts[:12]
        if not shown:
            canvas.setFillColor(MUTED)
            canvas.setFont("Times-Roman", 12)
            canvas.drawCentredString(
                root_x, self.height - 55, "No hosts were reported as discovered."
            )
            canvas.restoreState()
            return

        row_gap = 47
        for index, host in enumerate(shown):
            y = self.height - 68 - index * row_gap
            x = 14 if index % 2 == 0 else self.width - 174
            node_center = x + 80
            canvas.setStrokeColor(colors.HexColor("#9bb9ad"))
            canvas.line(root_x, self.height - 36, node_center, y + 29)
            canvas.setFillColor(colors.white)
            canvas.roundRect(x, y, 160, 42, 5, fill=1, stroke=1)
            canvas.setFillColor(INK)
            canvas.setFont("Times-Bold", 12)
            canvas.drawCentredString(node_center, y + 26, _plain(host.address)[:24])
            services = [
                f"{port.port}/{port.protocol}" for port in host.ports if port.state == "open"
            ][:6]
            canvas.setFillColor(MUTED)
            canvas.setFont("Times-Roman", 12)
            label = ", ".join(services) if services else "No open ports observed"
            canvas.drawCentredString(node_center, y + 9, label[:20])
        if len(self.hosts) > len(shown):
            canvas.setFillColor(MUTED)
            canvas.setFont("Times-Italic", 12)
            canvas.drawCentredString(
                root_x, 8, f"+ {len(self.hosts) - len(shown)} more host(s), listed in inventory"
            )
        canvas.restoreState()


class BarChart(Flowable):
    def __init__(self, title: str, counts: dict[str, int], palette: dict[str, colors.Color]):
        super().__init__()
        self.title = title
        self.counts = counts
        self.palette = palette
        self.width = 0
        self.height = max(60, 42 + len(counts) * 25)

    def wrap(self, available_width: float, available_height: float) -> tuple[float, float]:
        self.width = available_width
        return self.width, self.height

    def draw(self) -> None:
        canvas = self.canv
        canvas.saveState()
        canvas.setFillColor(INK)
        canvas.setFont("Times-Bold", 14)
        canvas.drawString(0, self.height - 10, self.title)
        max_count = max(self.counts.values(), default=0) or 1
        label_width = 76
        bar_width = max(30, self.width - label_width - 45)
        for index, (label, count) in enumerate(self.counts.items()):
            y = self.height - 34 - index * 25
            canvas.setFillColor(MUTED)
            canvas.setFont("Times-Roman", 12)
            canvas.drawString(0, y + 2, label.title())
            canvas.setFillColor(colors.HexColor("#edf1ef"))
            canvas.roundRect(label_width, y, bar_width, 14, 4, fill=1, stroke=0)
            if count:
                canvas.setFillColor(self.palette.get(label, EMERALD))
                canvas.roundRect(
                    label_width, y, bar_width * count / max_count, 14, 4, fill=1, stroke=0
                )
            canvas.setFillColor(INK)
            canvas.setFont("Times-Roman", 12)
            canvas.drawRightString(self.width, y + 2, str(count))
        canvas.restoreState()


class ReportCover(Flowable):
    """Draw a branded cover matching the Reports-page print design."""

    def __init__(
        self,
        target: str,
        completed: object,
        assessment_id: str,
        subtitle: str,
        prepared_by: str,
        footer: str,
        metrics: list[tuple[str, int]],
    ):
        super().__init__()
        self.target = _plain(target)
        if isinstance(completed, datetime):
            completed = completed.astimezone(UTC).strftime("%Y-%m-%d %H:%M UTC")
        self.completed = _plain(completed)
        self.assessment_id = _plain(assessment_id)
        self.subtitle = _plain(subtitle)
        self.prepared_by = _plain(prepared_by)
        self.footer = _plain(footer.replace("—", "-"))
        self.metrics = metrics
        self.width = 0
        self.height = 258 * mm
        self.logo = ImageReader(str(LOGO_PATH))

    def wrap(self, available_width: float, available_height: float) -> tuple[float, float]:
        self.width = available_width
        return self.width, self.height

    def draw(self) -> None:
        canvas = self.canv
        canvas.saveState()
        canvas.setFillColor(colors.HexColor("#07130b"))
        canvas.rect(0, 0, self.width, self.height, fill=1, stroke=0)

        canvas.saveState()
        clip = canvas.beginPath()
        clip.rect(0, 0, self.width, self.height)
        canvas.clipPath(clip, stroke=0, fill=0)
        canvas.setStrokeColor(colors.HexColor("#174b31"))
        canvas.setLineWidth(1)
        for radius in (78, 118, 158):
            canvas.circle(self.width + 3, self.height - 70, radius, stroke=1, fill=0)
        canvas.restoreState()

        left = 30
        canvas.setFillColor(colors.HexColor("#34d399"))
        canvas.roundRect(left, self.height - 112, 4, 66, 2, fill=1, stroke=0)
        self._draw_logo(canvas, left + 14, self.height - 112, 165, 66)

        canvas.setFillColor(colors.HexColor("#8de5b2"))
        canvas.setFont("Times-Bold", 12)
        kicker_lines = simpleSplit(self.subtitle.upper(), "Times-Bold", 12, self.width - left - 90)
        for index, line in enumerate(kicker_lines[:3]):
            canvas.drawString(left, self.height - 151 - index * 16, line)

        canvas.setFillColor(colors.white)
        canvas.setFont("Times-Bold", 40)
        canvas.drawString(left, self.height - 220, "Security Assessment")
        canvas.setFillColor(colors.HexColor("#69e2a2"))
        canvas.setFont("Times-Bold", 44)
        canvas.drawString(left, self.height - 269, "Report")

        canvas.setFillColor(colors.HexColor("#b0c1b6"))
        canvas.setFont("Times-Bold", 12)
        canvas.drawString(left, 362, "ASSESSMENT SNAPSHOT")
        card_gap = 9
        card_y = 282
        card_height = 62
        card_width = (self.width - left * 2 - card_gap * 2) / 3
        for index, (label, value) in enumerate(self.metrics):
            x = left + index * (card_width + card_gap)
            canvas.setFillColor(colors.HexColor("#0d2115"))
            canvas.setStrokeColor(colors.HexColor("#28513a"))
            canvas.roundRect(x, card_y, card_width, card_height, 7, fill=1, stroke=1)
            canvas.setFillColor(colors.HexColor("#34d399"))
            canvas.roundRect(x, card_y + card_height - 4, card_width, 4, 2, fill=1, stroke=0)
            canvas.setFillColor(colors.HexColor("#b0c1b6"))
            canvas.setFont("Times-Bold", 12)
            canvas.drawString(x + 11, card_y + 37, label)
            canvas.setFillColor(colors.white)
            canvas.setFont("Times-Bold", 24)
            canvas.drawString(x + 11, card_y + 10, str(value))

        rule_y = 226
        canvas.setStrokeColor(colors.HexColor("#405147"))
        canvas.line(left, rule_y, self.width - left, rule_y)
        column_width = (self.width - left * 2) / 3
        metadata = (
            ("ASSESSMENT TARGET", self.target),
            ("ASSESSMENT DATE", self.completed),
            ("PREPARED BY", self.prepared_by),
        )
        for index, (label, value) in enumerate(metadata):
            x = left + index * column_width
            canvas.setFillColor(colors.HexColor("#b0c1b6"))
            canvas.setFont("Times-Bold", 12)
            canvas.drawString(x, rule_y - 24, label)
            canvas.setFillColor(colors.white)
            canvas.setFont("Times-Roman", 13)
            lines = simpleSplit(value, "Times-Roman", 13, column_width - 12)
            for line_index, line in enumerate(lines[:3]):
                canvas.drawString(x, rule_y - 46 - line_index * 17, line)

        canvas.setFillColor(colors.HexColor("#b0c1b6"))
        canvas.setFont("Times-Roman", 12)
        footer_lines = simpleSplit(self.footer, "Times-Roman", 12, self.width - left * 2)
        for index, line in enumerate(footer_lines[:3]):
            canvas.drawString(left, 72 - index * 14, line)
        canvas.setFillColor(colors.HexColor("#8de5b2"))
        canvas.setFont("Times-Roman", 12)
        canvas.drawString(left, 25, f"ASSESSMENT ID  {self.assessment_id}")
        canvas.restoreState()

    def _draw_logo(self, canvas, x: float, y: float, width: float, height: float) -> None:
        canvas.drawImage(
            self.logo,
            x,
            y,
            width=width,
            height=height,
            preserveAspectRatio=True,
            anchor="c",
            mask="auto",
        )


class MetricCards(Flowable):
    def __init__(self, values: list[tuple[str, int]]):
        super().__init__()
        self.values = values
        self.width = 0
        self.height = 62

    def wrap(self, available_width: float, available_height: float) -> tuple[float, float]:
        self.width = available_width
        return self.width, self.height

    def draw(self) -> None:
        canvas = self.canv
        canvas.saveState()
        gap = 6
        card_width = (self.width - gap * (len(self.values) - 1)) / len(self.values)
        for index, (label, value) in enumerate(self.values):
            x = index * (card_width + gap)
            canvas.setStrokeColor(colors.HexColor("#dfe7e0"))
            canvas.setFillColor(colors.white)
            canvas.roundRect(x, 0, card_width, self.height - 2, 6, fill=1, stroke=1)
            canvas.setFillColor(EMERALD)
            canvas.roundRect(x, self.height - 5, card_width, 5, 2, fill=1, stroke=0)
            canvas.setFillColor(MUTED)
            canvas.setFont("Times-Roman", 12)
            canvas.drawString(x + 8, 34, label)
            canvas.setFillColor(INK)
            canvas.setFont("Times-Bold", 20)
            canvas.drawString(x + 8, 11, str(value))
        canvas.restoreState()


def _header_footer(canvas, doc) -> None:
    canvas.saveState()
    width, height = A4
    if doc.page == 1:
        canvas.restoreState()
        return
    canvas.setStrokeColor(EMERALD)
    canvas.setLineWidth(2)
    canvas.line(18 * mm, height - 12 * mm, width - 18 * mm, height - 12 * mm)
    canvas.setStrokeColor(colors.HexColor("#d9e3de"))
    canvas.line(18 * mm, 16 * mm, width - 18 * mm, 16 * mm)
    canvas.setFillColor(MUTED)
    canvas.setFont("Times-Roman", 12)
    canvas.drawString(18 * mm, 11 * mm, "NAJD Recon | Authorized assessment evidence")
    canvas.drawRightString(width - 18 * mm, 11 * mm, f"Page {doc.page}")
    canvas.restoreState()


def build_scan_pdf(job: ScanJob, settings: WorkspaceSettings | None = None) -> bytes:
    """Return a complete PDF, including scan metadata, charts and observed topology."""
    buffer = BytesIO()
    document = BaseDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=18 * mm,
        leftMargin=18 * mm,
        topMargin=18 * mm,
        bottomMargin=21 * mm,
        title=f"NAJD Recon assessment - {job.target}",
        author="NAJD Recon",
        subject="Authorized network reconnaissance and vulnerability assessment",
    )
    frame = Frame(
        document.leftMargin,
        document.bottomMargin,
        document.width,
        document.height,
        id="main",
        leftPadding=0,
        rightPadding=0,
        topPadding=0,
        bottomPadding=0,
    )
    document.addPageTemplates(
        [PageTemplate(id="assessment", frames=[frame], onPage=_header_footer)]
    )

    styles = getSampleStyleSheet()
    styles.add(
        ParagraphStyle(
            name="ReportTitle",
            parent=styles["Title"],
            fontName="Times-Bold",
            fontSize=30,
            leading=36,
            textColor=INK,
            alignment=TA_CENTER,
            spaceAfter=8,
        )
    )
    styles.add(
        ParagraphStyle(
            name="Section",
            parent=styles["Heading2"],
            fontName="Times-Bold",
            fontSize=18,
            leading=22,
            textColor=EMERALD,
            spaceBefore=10,
            spaceAfter=7,
            keepWithNext=True,
        )
    )
    styles.add(
        ParagraphStyle(
            name="Subsection",
            parent=styles["Heading3"],
            fontName="Times-Bold",
            fontSize=15,
            leading=19,
            textColor=INK,
            spaceBefore=7,
            spaceAfter=4,
            keepWithNext=True,
        )
    )
    styles.add(
        ParagraphStyle(
            name="BodySmall",
            parent=styles["BodyText"],
            fontName="Times-Roman",
            fontSize=12,
            leading=16,
            textColor=INK,
            spaceAfter=4,
            wordWrap="CJK",
        )
    )
    styles.add(
        ParagraphStyle(
            name="Cell",
            parent=styles["BodyText"],
            fontName="Times-Roman",
            fontSize=12,
            leading=15,
            textColor=INK,
            wordWrap="CJK",
        )
    )
    styles.add(
        ParagraphStyle(
            name="CellHeader",
            parent=styles["BodyText"],
            fontName="Times-Bold",
            fontSize=12,
            leading=15,
            textColor=colors.white,
        )
    )
    settings = settings or WorkspaceSettings()
    result = job.result
    hosts = result.hosts if result else []
    ports = [port for host in hosts for port in host.ports]
    cves = [(host, port, cve) for host in hosts for port in host.ports for cve in port.cves]
    severity_names = ("critical", "high", "medium", "low", "none", "unknown")
    severity_counts = {
        name: sum(getattr(cve.severity, "value", cve.severity) == name for _, _, cve in cves)
        for name in severity_names
    }
    state_counts = {
        name: sum(port.state == name for port in ports) for name in ("open", "closed", "filtered")
    }
    for host in hosts:
        for state_count in host.extra_port_states:
            if state_count.state in state_counts:
                state_counts[state_count.state] += state_count.count

    story = [
        ReportCover(
            job.target,
            job.finished_at or job.created_at,
            job.id,
            settings.report_subtitle or "Authorized Security Assessment",
            settings.report_contact or "Abdullah Bin Mohammad Mushtaq",
            settings.report_footer or "Confidential - For authorized recipients only",
            [
                ("HOSTS OBSERVED", len(hosts)),
                ("OPEN PORTS", state_counts["open"]),
                ("CVE INSTANCES", len(cves)),
            ],
        ),
        PageBreak(),
        _paragraph("Executive summary", styles["Section"]),
    ]

    metrics = MetricCards(
        [
            ("Open ports", state_counts["open"]),
            ("CVEs", len(cves)),
            ("Critical", severity_counts["critical"]),
            ("High", severity_counts["high"]),
            ("CISA KEV", sum(cve.in_kev for _, _, cve in cves)),
        ]
    )
    story.extend(
        [
            metrics,
            Spacer(1, 4 * mm),
        ]
    )

    summary = [
        ["Scanned target", _plain(job.target)],
        ["Resolved address", _plain(job.resolved_ip)],
        ["Scan result", _plain(result.summary if result and result.summary else "Completed")],
        ["Hosts observed", str(len(hosts))],
        [
            "Nmap host totals (up / down / total)",
            " / ".join(
                _plain(value)
                for value in (
                    result.hosts_up if result else None,
                    result.hosts_down if result else None,
                    result.hosts_total if result else None,
                )
            ),
        ],
        ["Open ports", str(state_counts["open"])],
        [
            "Closed / filtered ports reported",
            f"{state_counts['closed']} / {state_counts['filtered']}",
        ],
        [
            "Unique detected services",
            str(len({(p.service, p.product, p.version) for p in ports if p.service or p.product})),
        ],
        ["CVE instances", str(len(cves))],
        ["Critical / High", f"{severity_counts['critical']} / {severity_counts['high']}"],
        ["CISA KEV instances", str(sum(cve.in_kev for _, _, cve in cves))],
        ["Public exploit indicators", str(sum(cve.is_exploit for _, _, cve in cves))],
        [
            "Duration",
            f"{result.elapsed_seconds:.1f} seconds"
            if result and result.elapsed_seconds is not None
            else "Not available",
        ],
    ]
    summary_table = Table(
        [
            [_paragraph(key, styles["CellHeader"]), _paragraph(value, styles["BodySmall"])]
            for key, value in summary
        ],
        colWidths=[43 * mm, 125 * mm],
    )
    summary_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (0, -1), EMERALD),
                ("BACKGROUND", (1, 0), (1, -1), colors.HexColor("#f1f6f3")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#d9e3de")),
                ("LEFTPADDING", (0, 0), (-1, -1), 7),
                ("RIGHTPADDING", (0, 0), (-1, -1), 7),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ]
        )
    )
    story.extend(
        [
            summary_table,
            Spacer(1, 5 * mm),
            BarChart("CVE severity distribution", severity_counts, PALETTE),
            Spacer(1, 3 * mm),
            BarChart("Observed port states", state_counts, PALETTE),
            _paragraph("Observed network and services", styles["Section"]),
            _paragraph(
                "\n".join(
                    [
                        "This diagram summarizes the hosts and open services "
                        "returned by this scan.",
                        "It is not a network traffic map and does not establish that the hosts "
                        "communicate with one another. A port scan cannot determine all network "
                        "connections or routing.",
                    ]
                ),
                styles["BodySmall"],
            ),
            ObservationMap(job.target, hosts),
            _paragraph("Scan scope and methodology", styles["Section"]),
        ]
    )

    metadata_rows = [
        ("Resolved target", job.resolved_ip),
        ("Started", result.started_at if result and result.started_at else job.created_at),
        ("Finished", job.finished_at),
        ("Nmap version", result.nmap_version if result else None),
        ("Nmap command", " ".join(job.command)),
        ("Nmap-reported command", result.command if result else None),
        ("Scan options", "; ".join(f"{key}: {value}" for key, value in job.options.items())),
    ]
    story.append(
        Table(
            [
                [_paragraph(key, styles["CellHeader"]), _paragraph(value, styles["BodySmall"])]
                for key, value in metadata_rows
            ],
            colWidths=[43 * mm, 125 * mm],
            style=TableStyle(
                [
                    ("BACKGROUND", (0, 0), (0, -1), EMERALD),
                    ("BACKGROUND", (1, 0), (1, -1), colors.HexColor("#f1f6f3")),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#d9e3de")),
                    ("LEFTPADDING", (0, 0), (-1, -1), 7),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 7),
                    ("TOPPADDING", (0, 0), (-1, -1), 5),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ]
            ),
        )
    )

    story.extend([_paragraph("Host and port inventory", styles["Section"])])
    if not hosts:
        story.append(_paragraph("No hosts were reported by Nmap.", styles["BodySmall"]))
    for host in hosts:
        host_detail = f"{host.address} | status: {host.status}"
        if host.hostnames:
            host_detail += f" | names: {', '.join(host.hostnames)}"
        if host.status_reason:
            host_detail += f" | reason: {host.status_reason}"
            if host.status_reason_ttl is not None:
                host_detail += f" (TTL {host.status_reason_ttl})"
        if host.addresses:
            host_detail += " | addresses: " + ", ".join(
                f"{address.kind} {address.address}"
                + (f" ({address.vendor})" if address.vendor else "")
                for address in host.addresses
            )
        if host.os_matches:
            host_detail += " | OS: " + ", ".join(
                f"{match.name} ({match.accuracy}%)" for match in host.os_matches
            )
        if host.uptime_seconds is not None:
            host_detail += f" | uptime: {host.uptime_seconds}s"
        if host.uptime_last_boot:
            host_detail += f" | last boot: {host.uptime_last_boot}"
        if host.distance_hops is not None:
            host_detail += f" | distance: {host.distance_hops} hop(s)"
        story.append(_paragraph(host_detail, styles["Subsection"]))
        for state_count in host.extra_port_states:
            reasons = f" ({', '.join(state_count.reasons)})" if state_count.reasons else ""
            story.append(
                _paragraph(
                    f"Additional ports reported {state_count.state}: {state_count.count}{reasons}",
                    styles["BodySmall"],
                )
            )
        if host.trace_hops:
            trace = " → ".join(
                f"{hop.ttl}: {hop.hostname or hop.address or '*'}"
                + (f" ({hop.rtt} ms)" if hop.rtt else "")
                for hop in host.trace_hops
            )
            story.append(_paragraph(f"Observed route hops: {trace}", styles["BodySmall"]))
        if not host.ports:
            story.append(_paragraph("No ports reported for this host.", styles["BodySmall"]))
            continue
        data = [
            [
                _paragraph(label, styles["CellHeader"])
                for label in ("Port", "State", "Service", "Product / version", "CVE count")
            ]
        ]
        for port in host.ports:
            service_details = [
                " ".join(filter(None, (port.product, port.version, port.extrainfo)))
                or "Not identified",
                f"State reason: {port.reason}"
                + (f" (TTL {port.reason_ttl})" if port.reason_ttl is not None else "")
                if port.reason
                else None,
                (
                    f"Detection: {port.service_method or 'unknown'} "
                    f"(confidence {port.service_confidence})"
                    if port.service_method or port.service_confidence is not None
                    else None
                ),
                f"Tunnel: {port.service_tunnel}" if port.service_tunnel else None,
                f"CPE: {', '.join(port.cpes)}" if port.cpes else None,
            ]
            data.append(
                [
                    _paragraph(f"{port.port}/{port.protocol}", styles["Cell"]),
                    _paragraph(port.state, styles["Cell"]),
                    _paragraph(port.service or "Unknown", styles["Cell"]),
                    _paragraph("\n".join(filter(None, service_details)), styles["Cell"]),
                    _paragraph(str(len(port.cves)), styles["Cell"]),
                ]
            )
        table = LongTable(
            data, colWidths=[22 * mm, 20 * mm, 35 * mm, 73 * mm, 18 * mm], repeatRows=1
        )
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), EMERALD),
                    (
                        "ROWBACKGROUNDS",
                        (0, 1),
                        (-1, -1),
                        [colors.white, colors.HexColor("#f5f8f6")],
                    ),
                    ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#d9e3de")),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("LEFTPADDING", (0, 0), (-1, -1), 4),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                    ("TOPPADDING", (0, 0), (-1, -1), 4),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ]
            )
        )
        story.extend([table, Spacer(1, 3 * mm)])

    script_rows = []
    for host in hosts:
        script_rows.extend(
            [f"{host.address} · host", script.id, script.output] for script in host.scripts
        )
        for port in host.ports:
            scope = f"{host.address} · {port.port}/{port.protocol}"
            script_rows.extend([scope, script.id, script.output] for script in port.scripts)

    story.append(_paragraph("Nmap script observations", styles["Section"]))
    if script_rows:
        scripts_table = LongTable(
            [
                [
                    _paragraph(label, styles["CellHeader"])
                    for label in ("Host / port", "Script", "Output")
                ],
                *[
                    [
                        _paragraph(scope, styles["Cell"]),
                        _paragraph(script_id, styles["Cell"]),
                        _paragraph(output or "No script output", styles["Cell"]),
                    ]
                    for scope, script_id, output in script_rows
                ],
            ],
            colWidths=[42 * mm, 31 * mm, 95 * mm],
            repeatRows=1,
            splitByRow=1,
        )
        scripts_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), EMERALD),
                    (
                        "ROWBACKGROUNDS",
                        (0, 1),
                        (-1, -1),
                        [colors.white, colors.HexColor("#f5f8f6")],
                    ),
                    ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#d9e3de")),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("LEFTPADDING", (0, 0), (-1, -1), 5),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                    ("TOPPADDING", (0, 0), (-1, -1), 5),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ]
            )
        )
        story.append(scripts_table)
    else:
        story.append(_paragraph("No Nmap scripts returned output.", styles["BodySmall"]))

    story.append(_paragraph("Complete vulnerability register", styles["Section"]))
    if not cves:
        story.append(
            _paragraph("No CVE instances were reported in this scan.", styles["BodySmall"])
        )
    else:
        cve_rows = [
            [
                _paragraph(label, styles["CellHeader"])
                for label in (
                    "CVE / host / service",
                    "Risk / scores / indicators",
                    "Description and references",
                )
            ]
        ]
        for host, port, cve in cves:
            references = "; ".join(cve.references) or cve.url or "Not available"
            cve_rows.append(
                [
                    _paragraph(
                        f"{_plain(cve.id)}\n{_plain(host.address)}\n"
                        f"{port.port}/{_plain(port.protocol)} {_plain(port.service or 'unknown')}"
                        f"\n{_plain(port.product or '')} {_plain(port.version or '')}",
                        styles["Cell"],
                    ),
                    _paragraph(
                        f"Severity: {_plain(getattr(cve.severity, 'value', cve.severity))}"
                        f"\nCVSS: {_plain(cve.cvss)} ({_plain(cve.cvss_version)})"
                        f"\nEPSS: {_plain(cve.epss)}"
                        f"\nEPSS percentile: {_plain(cve.epss_percentile)}"
                        f"\nCISA KEV: {'Yes' if cve.in_kev else 'No'}"
                        f"\nKEV date added: {_plain(cve.kev_date_added)}"
                        f"\nRansomware use: {'Yes' if cve.kev_ransomware else 'No'}"
                        f"\nPublic exploit: {'Yes' if cve.is_exploit else 'No'}"
                        f"\nSource: {_plain(cve.source)}"
                        f"\nPublished: {_plain(cve.published)}",
                        styles["Cell"],
                    ),
                    _paragraph(
                        f"{_plain(cve.description)}"
                        f"\nCVSS vector: {_plain(cve.cvss_vector)}"
                        f"\nCWE: {_plain(', '.join(cve.cwe) or 'Not available')}"
                        f"\nReferences: {_plain(references)}"
                        f"\nCVE URL: {_plain(cve.url)}",
                        styles["Cell"],
                    ),
                ]
            )
        vulnerability_table = LongTable(
            cve_rows,
            colWidths=[47 * mm, 45 * mm, 76 * mm],
            repeatRows=1,
            splitByRow=1,
        )
        vulnerability_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), EMERALD),
                    (
                        "ROWBACKGROUNDS",
                        (0, 1),
                        (-1, -1),
                        [colors.white, colors.HexColor("#f5f8f6")],
                    ),
                    ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#d9e3de")),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("LEFTPADDING", (0, 0), (-1, -1), 5),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                    ("TOPPADDING", (0, 0), (-1, -1), 5),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ]
            )
        )
        story.append(vulnerability_table)

    story.extend(
        [
            _paragraph("Interpretation and limitations", styles["Section"]),
            _paragraph(
                "\n".join(
                    [
                        "This report records Nmap observations and vulnerability intelligence "
                        "available when the scan ran. Version-based CVE matching is indicative, "
                        "not proof of exploitability; vendors may backport fixes without changing "
                        "version strings.",
                        "Confirm patch level and exposure with the asset owner before remediation "
                        "decisions. Hosts and services shown are only those returned within this "
                        "scan's scope and configuration. Missing observations do not prove "
                        "absence or remediation.",
                    ]
                ),
                styles["BodySmall"],
            ),
        ]
    )

    document.build(story)
    return buffer.getvalue()
