# frozen_string_literal: true

# Security regression check for the generated GitHub Pages site.
# Run after `bundle exec jekyll build` or via `npm run check:security`.

ROOT = File.expand_path("..", __dir__)
SITE_DIR = File.join(ROOT, "_site")
SOURCE_EXTENSIONS = %w[.html .md .yml .yaml .js .scss .css].freeze
BANNED_SERVICE = /polyfill[.]io/i
BANNED_EMAILS = /(?:qwc\x40ruc[.]edu[.]cn|q-zeus\x40foxmail[.]com)/i
SAME_ORIGIN = %r{\A(?:/|https://e-qin[.]github[.]io/)}i

errors = []

Dir.glob(File.join(ROOT, "**", "*"), File::FNM_DOTMATCH).each do |path|
  next unless File.file?(path)
  next unless SOURCE_EXTENSIONS.include?(File.extname(path))
  next if path.start_with?(File.join(ROOT, ".git"), File.join(ROOT, "vendor"), SITE_DIR)

  File.foreach(path).with_index(1) do |line, number|
    errors << "#{path.delete_prefix(ROOT + "/")}:#{number}: banned Polyfill.io reference" if line.match?(BANNED_SERVICE)
    errors << "#{path.delete_prefix(ROOT + "/")}:#{number}: unobfuscated contact email" if line.match?(BANNED_EMAILS)
  end
end

unless Dir.exist?(SITE_DIR)
  warn "_site is missing; build the site before running the security check."
  exit 2
end

Dir.glob(File.join(SITE_DIR, "**", "*.html")).each do |path|
  html = File.read(path)
  html.scan(/<script\b[^>]*\bsrc=["']([^"']+)["']/i).flatten.each do |src|
    next if src.match?(SAME_ORIGIN)

    errors << "#{path.delete_prefix(ROOT + "/")}: third-party script source #{src.inspect}"
  end
end

if errors.empty?
  puts "Security check passed: no Polyfill.io references, exposed contact email, or third-party executable scripts."
else
  warn errors.join("\n")
  exit 1
end
