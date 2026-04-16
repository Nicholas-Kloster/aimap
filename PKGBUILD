# Maintainer: Nicholas Kloster <security@d5data.ai>

pkgname=aimap
pkgver=1.1.1
pkgrel=1
groups=('blackarch' 'blackarch-scanner' 'blackarch-recon' 'blackarch-networking')
pkgdesc='Security scanner for AI and ML infrastructure. Fingerprints 23 AI/ML service types (LLMs, vector databases, model servers) and surfaces actionable findings.'
arch=('x86_64' 'aarch64')
url='https://github.com/Nicholas-Kloster/aimap'
license=('MIT')
makedepends=('go')
source=("$pkgname-$pkgver.tar.gz::https://github.com/Nicholas-Kloster/aimap/archive/v$pkgver.tar.gz")
sha256sums=('c1a48b61524f1f3d4c5e046c1a84189db36e55bce1900ede1107cfbabbb1246c')

build() {
  cd "$pkgname-$pkgver"
  export CGO_ENABLED=0
  export GOFLAGS="-trimpath -mod=readonly -modcacherw"
  export LDFLAGS="-buildmode=pie -linkmode=external -s -w"
  go build -o "$pkgname" .
}

package() {
  cd "$pkgname-$pkgver"

  # Binary
  install -Dm755 "$pkgname" "$pkgdir/usr/bin/$pkgname"

  # Man page
  if [ -f "aimap.1" ]; then
    install -Dm644 "aimap.1" "$pkgdir/usr/share/man/man1/aimap.1"
  fi

  # License
  install -Dm644 "LICENSE" "$pkgdir/usr/share/licenses/$pkgname/LICENSE"

  # Documentation
  install -Dm644 "README.md" "$pkgdir/usr/share/doc/$pkgname/README.md"
}
