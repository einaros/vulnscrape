class Array
  def uniq_by
    h = {};
    inject([]) {|a,x| h[yield(x)] ||= a << x}
  end
end

class String
  def self.random length
    (0...length).map{ ('a'..'z').to_a[rand(26)] }.join
  end
  def each_match regex, &block
    md = regex.match(self)
    offset = 0
    while md
      block.call(md, offset + md.offset(0)[0])
      offset += md.offset(0)[1]
      md = regex.match(md.post_match)
    end
  end
  def map_match regex, &block
    md = regex.match(self)
    offset = 0
    a = []
    while md
      a << block.call(md, offset + md.offset(0)[0])
      offset += md.offset(0)[1]
      md = regex.match(md.post_match)
    end
    a
  end
end