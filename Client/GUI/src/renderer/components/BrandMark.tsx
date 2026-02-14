import logoUrl from "../assets/logo.png";

const BrandMark = ({
  className = "",
  label = "Aydo Security"
}: {
  className?: string;
  label?: string;
}) => {
  return (
    <span className={`relative inline-flex ${className}`} aria-label={label} role="img">
      <span
        className="brand-mark absolute inset-0"
        style={{
          WebkitMaskImage: `url(${logoUrl})`,
          maskImage: `url(${logoUrl})`,
          WebkitMaskRepeat: "no-repeat",
          maskRepeat: "no-repeat",
          WebkitMaskSize: "contain",
          maskSize: "contain",
          WebkitMaskPosition: "center",
          maskPosition: "center",
          backgroundColor: "rgb(var(--color-accent))"
        }}
      />
      <img src={logoUrl} alt={label} className="brand-mark-fallback h-full w-full object-contain" />
    </span>
  );
};

export default BrandMark;
