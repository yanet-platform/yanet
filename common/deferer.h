namespace utils
{

template<typename F>
class Deferer
{
	F action_;

public:
	Deferer(F&& action) :
	        action_{std::move(action)}
	{}
	Deferer(const Deferer& other) = delete;
	Deferer(Deferer&& other) = delete;
	Deferer& operator=(const Deferer& other) = delete;
	Deferer& operator=(Deferer&& other) = delete;
	~Deferer()
	{
		action_();
	}
};

} // namespace utils