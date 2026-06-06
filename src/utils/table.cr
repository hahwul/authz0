require "colorize"
require "html"

module Authz0
  # Minimal text table renderer. Two output styles:
  #   * :box      — Unicode box-drawing borders (default, for terminals)
  #   * :markdown — GitHub-flavored Markdown pipe table
  #
  # Per-row coloring is supported for the box style so the scanner can paint
  # vulnerable rows red. Column widths are computed from the *visible* string
  # length (color escapes are applied after measuring).
  class Table
    enum Style
      Box
      Markdown
    end

    getter headers : Array(String)
    getter rows : Array(Array(String))

    def initialize(@headers : Array(String))
      @rows = [] of Array(String)
      @row_colors = [] of Colorize::Color?
      @aligns = Array(Symbol).new(@headers.size, :left)
    end

    # Set per-column alignment (:left or :right). Extra entries are ignored.
    def align(aligns : Array(Symbol))
      aligns.each_with_index do |a, i|
        @aligns[i] = a if i < @aligns.size
      end
      self
    end

    def add(row : Array(String), color : Colorize::Color? = nil)
      # Pad/truncate to the header arity so a short row can't desync columns,
      # and collapse interior line terminators so one cell can't split a row
      # across lines (breaking box/markdown alignment or forging a table row).
      normalized = Array(String).new(@headers.size) { |i| Table.oneline(row[i]? || "") }
      @rows << normalized
      @row_colors << color
      self
    end

    # Flatten a cell to a single line: CR/LF/tab → a single space. Tables are
    # one-row-per-line, so an embedded newline would otherwise wrap the row.
    def self.oneline(cell : String) : String
      return cell unless cell.includes?('\n') || cell.includes?('\r') || cell.includes?('\t')
      cell.gsub(/[\r\n\t]+/, " ")
    end

    def render(style : Style = Style::Box, color : Bool = true) : String
      widths = column_widths
      case style
      when .markdown?
        render_markdown(widths)
      else
        render_box(widths, color)
      end
    end

    private def column_widths : Array(Int32)
      widths = @headers.map { |h| Table.display_width(h) }
      @rows.each do |row|
        row.each_with_index do |cell, i|
          w = Table.display_width(cell)
          widths[i] = w if w > widths[i]
        end
      end
      widths
    end

    # Pad based on *display* width (columns a terminal renders), not codepoint
    # count, so a column of CJK/wide glyphs still lines up with ASCII rows.
    private def pad(cell : String, width : Int32, align : Symbol) : String
      gap = width - Table.display_width(cell)
      gap = 0 if gap < 0
      case align
      when :right
        (" " * gap) + cell
      when :center
        left = gap // 2
        (" " * left) + cell + (" " * (gap - left))
      else
        cell + (" " * gap)
      end
    end

    # Terminal display width of a string: most East-Asian / fullwidth glyphs
    # occupy two cells, zero-width combining marks occupy none, everything
    # else one. A pragmatic subset of the Unicode East_Asian_Width table —
    # enough to keep CJK report tables aligned.
    def self.display_width(str : String) : Int32
      width = 0
      str.each_char do |c|
        cp = c.ord
        next if cp == 0
        if combining?(cp)
          # zero-width
        elsif wide?(cp)
          width += 2
        else
          width += 1
        end
      end
      width
    end

    private def self.combining?(cp : Int32) : Bool
      (0x0300 <= cp <= 0x036F) ||   # combining diacritical marks
        (0x200B <= cp <= 0x200F) || # zero-width space/joiners/marks
        (0xFE00 <= cp <= 0xFE0F)    # variation selectors
    end

    private def self.wide?(cp : Int32) : Bool
      (0x1100 <= cp <= 0x115F) ||     # Hangul Jamo
        (0x2E80 <= cp <= 0x303E) ||   # CJK radicals … symbols
        (0x3041 <= cp <= 0x33FF) ||   # Hiragana/Katakana/CJK symbols
        (0x3400 <= cp <= 0x4DBF) ||   # CJK Ext A
        (0x4E00 <= cp <= 0x9FFF) ||   # CJK Unified
        (0xA000 <= cp <= 0xA4CF) ||   # Yi
        (0xAC00 <= cp <= 0xD7A3) ||   # Hangul syllables
        (0xF900 <= cp <= 0xFAFF) ||   # CJK compatibility
        (0xFE30 <= cp <= 0xFE4F) ||   # CJK compatibility forms
        (0xFF00 <= cp <= 0xFF60) ||   # fullwidth forms
        (0xFFE0 <= cp <= 0xFFE6) ||   # fullwidth signs
        (0x1F300 <= cp <= 0x1FAFF) || # emoji & pictographs
        (0x20000 <= cp <= 0x3FFFD)    # CJK Ext B+ (supplementary)
    end

    private def render_box(widths : Array(Int32), color : Bool) : String
      String.build do |io|
        io << border(widths, "┌", "┬", "┐") << '\n'
        io << "│ " << @headers.map_with_index { |h, i| pad(h, widths[i], @aligns[i]) }.join(" │ ") << " │" << '\n'
        io << border(widths, "├", "┼", "┤") << '\n'
        @rows.each_with_index do |row, ri|
          cells = row.map_with_index { |c, i| pad(c, widths[i], @aligns[i]) }
          line = "│ " + cells.join(" │ ") + " │"
          rc = @row_colors[ri]?
          if color && rc
            io << line.colorize(rc).to_s << '\n'
          else
            io << line << '\n'
          end
        end
        io << border(widths, "└", "┴", "┘")
      end
    end

    private def border(widths : Array(Int32), left : String, mid : String, right : String) : String
      String.build do |io|
        io << left
        widths.each_with_index do |w, i|
          io << "─" * (w + 2)
          io << (i == widths.size - 1 ? right : mid)
        end
      end
    end

    # A markdown table cell: neutralize inline HTML, then escape the pipe so it
    # can't break out of the column.
    private def md_cell(s : String) : String
      HTML.escape(s).gsub('|', "\\|")
    end

    private def render_markdown(_widths : Array(Int32)) : String
      # Escape cells FIRST, then size the columns on the escaped text — otherwise
      # padding is computed from the shorter raw cell and the escaped row is
      # wider than its column, producing ragged source. HTML-escape too: a
      # markdown table cell otherwise passes raw inline HTML (e.g. <script>)
      # through to renderers that don't sanitize (CI dashboards, static sites).
      esc_headers = @headers.map { |h| md_cell(h) }
      esc_rows = @rows.map { |row| row.map { |c| md_cell(c) } }

      widths = esc_headers.map { |h| Table.display_width(h) }
      esc_rows.each do |row|
        row.each_with_index do |cell, i|
          w = Table.display_width(cell)
          widths[i] = w if w > widths[i]
        end
      end

      String.build do |io|
        io << "| " << esc_headers.map_with_index { |h, i| pad(h, widths[i], @aligns[i]) }.join(" | ") << " |" << '\n'
        sep = widths.map_with_index do |w, i|
          case @aligns[i]
          when :right  then "-" * (w + 1) + ":"
          when :center then ":" + "-" * w + ":"
          else              "-" * (w + 2)
          end
        end
        io << "|" << sep.join("|") << "|" << '\n'
        esc_rows.each_with_index do |row, ri|
          cells = row.map_with_index { |c, i| pad(c, widths[i], @aligns[i]) }
          io << "| " << cells.join(" | ") << " |"
          io << '\n' unless ri == esc_rows.size - 1
        end
      end
    end
  end
end
